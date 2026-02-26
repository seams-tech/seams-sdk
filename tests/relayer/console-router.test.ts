import { test, expect } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleWebhookService,
  createPostgresConsoleBillingService,
  createPostgresConsoleWebhookService,
  type ConsoleAuthAdapter,
  type ConsoleBillingService,
  type ConsoleWebhookService,
} from '@server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, getPath, startExpressRouter } from './helpers';
import { getPostgresPool } from '../../server/src/storage/postgres';

function makeConsoleAuthAdapter(
  roles: string[],
  orgId = 'org-1',
  userId = 'user-1',
): ConsoleAuthAdapter {
  return {
    authenticate: async () => ({
      ok: true,
      claims: {
        userId,
        orgId,
        roles,
      },
    }),
  };
}

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

test.describe('console router (express)', () => {
  test('GET /console/healthz works and relay paths are isolated', async () => {
    const router = createConsoleRouter({ healthz: true });
    const srv = await startExpressRouter(router);
    try {
      const health = await fetchJson(`${srv.baseUrl}/console/healthz`, { method: 'GET' });
      expect(health.status).toBe(200);
      expect(health.json?.service).toBe('console');

      const relayPath = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(relayPath.status).toBe(404);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/webhooks returns webhooks_not_configured without webhook service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('webhooks_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/api-keys returns api_keys_not_configured without API key service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/api-keys`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('api_keys_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('API key lifecycle works and secrets are reveal-once on create/rotate', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'server-key',
          environmentId: 'prod',
          scopes: ['wallets:read', 'billing:read'],
          ipAllowlist: ['203.0.113.10/32'],
        }),
      });
      expect(created.status).toBe(201);
      const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
      const createdSecret = String(getPath(created.json, 'secret') || '');
      expect(keyId).toBeTruthy();
      expect(createdSecret).toContain('tsk_');
      expect(Number(getPath(created.json, 'apiKey', 'secretVersion') || 0)).toBe(1);

      const listed = await fetchJson(`${srv.baseUrl}/console/api-keys`, { method: 'GET' });
      expect(listed.status).toBe(200);
      expect(Array.isArray(listed.json?.apiKeys)).toBe(true);
      expect(String(getPath(listed.json, 'apiKeys', 0, 'id') || '')).toBe(keyId);
      expect(getPath(listed.json, 'apiKeys', 0, 'secret')).toBeUndefined();

      const rotated = await fetchJson(`${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'scheduled rotation' }),
      });
      expect(rotated.status).toBe(200);
      const rotatedSecret = String(getPath(rotated.json, 'secret') || '');
      expect(rotatedSecret).toContain('tsk_');
      expect(rotatedSecret).not.toBe(createdSecret);
      expect(Number(getPath(rotated.json, 'apiKey', 'secretVersion') || 0)).toBe(2);

      const revoked = await fetchJson(`${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}`, {
        method: 'DELETE',
      });
      expect(revoked.status).toBe(200);
      expect(getPath(revoked.json, 'revoked')).toBe(true);
      expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');

      const rotateRevoked = await fetchJson(`${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`, {
        method: 'POST',
      });
      expect(rotateRevoked.status).toBe(409);
      expect(rotateRevoked.json?.code).toBe('api_key_revoked');
    } finally {
      await srv.close();
    }
  });

  test('webhook endpoint CRUD, deliveries, and replay flow works', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/hook',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const listed = await fetchJson(`${srv.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const endpoints = Array.isArray(listed.json?.endpoints) ? listed.json?.endpoints : [];
      expect(endpoints.length).toBe(1);
      expect(String(getPath(listed.json, 'endpoints', 0, 'id') || '')).toBe(endpointId);

      const emitted = await webhooks.emitEvent({
        orgId: 'org-1',
        actorUserId: 'system-webhooks-test',
        roles: ['ops'],
      }, {
        eventType: 'billing.invoice.paid',
        payload: {
          invoiceId: 'inv_router_1',
        },
      });
      expect(emitted.attempted).toBe(1);
      expect(emitted.delivered).toBe(0);
      expect(emitted.failed).toBe(1);

      const deliveries = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`, {
        method: 'GET',
      });
      expect(deliveries.status).toBe(200);
      const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
      expect(rows.length).toBe(1);
      expect(String(getPath(deliveries.json, 'deliveries', 0, 'status') || '')).toBe('FAILED');
      expect(Number(getPath(deliveries.json, 'deliveries', 0, 'attemptCount') || 0)).toBe(1);
      const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
      expect(deliveryId).toBeTruthy();

      const attemptsBeforeReplay = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts`, {
        method: 'GET',
      });
      expect(attemptsBeforeReplay.status).toBe(200);
      expect(Number(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
      expect(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'status')).toBe('FAILED');

      const unresolvedDlq = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`, {
        method: 'GET',
      });
      expect(unresolvedDlq.status).toBe(200);
      const unresolvedRows = Array.isArray(unresolvedDlq.json?.deadLetters) ? unresolvedDlq.json?.deadLetters : [];
      expect(unresolvedRows.length).toBe(1);
      expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
      expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'resolvedAt')).toBeNull();

      const replayed = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deliveryId }),
      });
      expect(replayed.status).toBe(200);
      expect(getPath(replayed.json, 'replay', 'replayed')).toBe(true);
      expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');
      expect(Number(getPath(replayed.json, 'replay', 'delivery', 'attemptCount') || 0)).toBe(2);
      expect(Number(getPath(replayed.json, 'replay', 'delivery', 'replayCount') || 0)).toBe(1);

      const attemptsAfterReplay = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1`, {
        method: 'GET',
      });
      expect(attemptsAfterReplay.status).toBe(200);
      const replayAttempts = Array.isArray(attemptsAfterReplay.json?.attempts) ? attemptsAfterReplay.json?.attempts : [];
      expect(replayAttempts.length).toBe(1);
      expect(Number(getPath(attemptsAfterReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(2);
      expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'status')).toBe('SUCCEEDED');
      expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'isReplay')).toBe(true);
      const attemptsNextCursor = String(attemptsAfterReplay.json?.nextCursor || '');
      expect(attemptsNextCursor).toBeTruthy();

      const attemptsSecondPage = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1&cursor=${encodeURIComponent(attemptsNextCursor)}`, {
        method: 'GET',
      });
      expect(attemptsSecondPage.status).toBe(200);
      const replayAttemptsSecondPage = Array.isArray(attemptsSecondPage.json?.attempts)
        ? attemptsSecondPage.json?.attempts
        : [];
      expect(replayAttemptsSecondPage.length).toBe(1);
      expect(Number(getPath(attemptsSecondPage.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
      expect(String(attemptsSecondPage.json?.nextCursor || '')).toBe('');

      const unresolvedAfterReplay = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`, {
        method: 'GET',
      });
      expect(unresolvedAfterReplay.status).toBe(200);
      const unresolvedRowsAfterReplay = Array.isArray(unresolvedAfterReplay.json?.deadLetters)
        ? unresolvedAfterReplay.json?.deadLetters
        : [];
      expect(unresolvedRowsAfterReplay.length).toBe(0);

      const resolvedDlq = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?includeResolved=true`, {
        method: 'GET',
      });
      expect(resolvedDlq.status).toBe(200);
      const resolvedRows = Array.isArray(resolvedDlq.json?.deadLetters) ? resolvedDlq.json?.deadLetters : [];
      expect(resolvedRows.length).toBe(1);
      expect(getPath(resolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
      expect(Boolean(getPath(resolvedDlq.json, 'deadLetters', 0, 'resolvedAt'))).toBe(true);

      const updated = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: 'DISABLED',
          subscriptions: ['wallet', 'policy'],
        }),
      });
      expect(updated.status).toBe(200);
      expect(getPath(updated.json, 'endpoint', 'status')).toBe('DISABLED');

      const emittedDisabled = await webhooks.emitEvent({
        orgId: 'org-1',
        actorUserId: 'system-webhooks-test',
        roles: ['ops'],
      }, {
        eventType: 'billing.invoice.paid',
        payload: {
          invoiceId: 'inv_router_2',
        },
      });
      expect(emittedDisabled.attempted).toBe(0);
      expect(emittedDisabled.delivered).toBe(0);
      expect(emittedDisabled.failed).toBe(0);

      const deleted = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`, {
        method: 'DELETE',
      });
      expect(deleted.status).toBe(200);
      expect(deleted.json?.removed).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('webhook list endpoints reject malformed cursor', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks: createInMemoryConsoleWebhookService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/bad-cursor-express',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const deliveries = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=bad_cursor`, {
        method: 'GET',
      });
      expect(deliveries.status).toBe(400);
      expect(deliveries.json?.code).toBe('invalid_query');

      const attempts = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=bad_cursor`, {
        method: 'GET',
      });
      expect(attempts.status).toBe(400);
      expect(attempts.json?.code).toBe('invalid_query');

      const deadLetters = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?cursor=bad_cursor`, {
        method: 'GET',
      });
      expect(deadLetters.status).toBe(400);
      expect(deadLetters.json?.code).toBe('invalid_query');

      const oversizedSortKey = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=9007199254740992%3Aoverflow`,
        {
          method: 'GET',
        },
      );
      expect(oversizedSortKey.status).toBe(400);
      expect(oversizedSortKey.json?.code).toBe('invalid_query');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/stablecoins/assets requires console auth adapter', async () => {
    const router = createConsoleRouter({});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/assets`, { method: 'GET' });
      expect(res.status).toBe(503);
      expect(res.json?.code).toBe('console_auth_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/stablecoins/assets returns supported assets/chains', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/assets`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.json?.version).toBe('v1');
      const assets = Array.isArray(res.json?.assets) ? res.json?.assets : [];
      expect(assets.length).toBe(2);
      expect(JSON.stringify(assets)).toContain('"asset":"USDC"');
      expect(JSON.stringify(assets)).toContain('"chain":"Ethereum"');
      expect(JSON.stringify(assets)).toContain('"requiredConfirmations":12');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/payment-methods requires admin role', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['billing_admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/payment-methods returns billing_not_configured without billing service', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/webhook requires configured shared secret', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId: 'evt_missing_secret',
          providerRef: 'pi_provider_missing',
          providerStatus: 'SUCCEEDED',
        }),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('stripe_webhook_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('billing flow: card methods + stablecoin intent + rail lock conflict', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const addCard = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerRef: 'pm_test_123',
          brand: 'visa',
          last4: '4242',
          expMonth: 12,
          expYear: 2030,
        }),
      });
      expect(addCard.status).toBe(201);
      expect(String(getPath(addCard.json, 'paymentMethod', 'id') || '')).toBeTruthy();

      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Base',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const stablecoinIntent = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          quoteId,
        }),
      });
      expect(stablecoinIntent.status).toBe(201);
      expect(getPath(stablecoinIntent.json, 'paymentIntent', 'rail')).toBe('STABLECOIN');

      const stripeIntent = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
        }),
      });
      expect(stripeIntent.status).toBe(409);
      expect(stripeIntent.json?.code).toBe('invoice_rail_locked');
    } finally {
      await srv.close();
    }
  });

  test('stablecoin quote is single-use across payment intents', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const firstIntent = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId, quoteId }),
      });
      expect(firstIntent.status).toBe(201);
      const paymentIntentId = String(getPath(firstIntent.json, 'paymentIntent', 'id') || '');
      expect(paymentIntentId).toBeTruthy();

      const canceled = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/cancel`, {
        method: 'POST',
      });
      expect(canceled.status).toBe(200);
      expect(getPath(canceled.json, 'paymentIntent', 'state')).toBe('CANCELED');

      const reused = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId, quoteId }),
      });
      expect(reused.status).toBe(409);
      expect(reused.json?.code).toBe('quote_already_consumed');
    } finally {
      await srv.close();
    }
  });

  test('Stripe webhook reconciles payment intent by providerRef and dedupes event id', async () => {
    const billing = createInMemoryConsoleBillingService();
    const secret = 'whsec_console_router_test';
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      billingStripeWebhookSecret: secret,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(created.status).toBe(201);
      const providerRef = String(getPath(created.json, 'paymentIntent', 'providerRef') || '');
      const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
      expect(providerRef).toBeTruthy();
      expect(amountMinor).toBeGreaterThan(0);

      const unauthorized = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId: 'evt_express_webhook_unauthorized',
          providerRef,
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
        }),
      });
      expect(unauthorized.status).toBe(401);
      expect(unauthorized.json?.code).toBe('unauthorized');

      const eventId = `evt_express_webhook_${Date.now()}`;
      const first = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': secret,
        },
        body: JSON.stringify({
          eventId,
          providerRef,
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
        }),
      });
      expect(first.status).toBe(200);
      expect(first.json?.accepted).toBe(true);
      expect(getPath(first.json, 'paymentIntent', 'state')).toBe('SETTLED');

      const duplicate = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': secret,
        },
        body: JSON.stringify({
          eventId,
          providerRef,
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
        }),
      });
      expect(duplicate.status).toBe(200);
      expect(duplicate.json?.accepted).toBe(false);
      expect(getPath(duplicate.json, 'paymentIntent', 'state')).toBe('SETTLED');
    } finally {
      await srv.close();
    }
  });

  test('stripe payment intents reject concurrent active attempts', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const firstIntent = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(firstIntent.status).toBe(201);
      expect(getPath(firstIntent.json, 'paymentIntent', 'state')).toBe('CREATED');

      const secondIntent = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(secondIntent.status).toBe(409);
      expect(secondIntent.json?.code).toBe('active_payment_intent_exists');
    } finally {
      await srv.close();
    }
  });

  test('billing usage endpoints compute MAW with exclusions and idempotency', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const e1 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_1',
          action: 'transfer',
          succeeded: true,
          sourceEventId: 'usage_evt_1',
        }),
      });
      expect(e1.status).toBe(200);
      expect(getPath(e1.json, 'result', 'accepted')).toBe(true);
      expect(getPath(e1.json, 'result', 'counted')).toBe(true);
      expect(Number(getPath(e1.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);
      const monthUtc = String(getPath(e1.json, 'result', 'monthUtc') || '');
      expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

      const e2 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_1',
          action: 'swap',
          succeeded: true,
          sourceEventId: 'usage_evt_2',
        }),
      });
      expect(e2.status).toBe(200);
      expect(Number(getPath(e2.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);

      const e3 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_2',
          action: 'approve',
          succeeded: true,
          sourceEventId: 'usage_evt_3',
        }),
      });
      expect(e3.status).toBe(200);
      expect(Number(getPath(e3.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const excluded = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_3',
          action: 'wallet_created',
          succeeded: true,
          sourceEventId: 'usage_evt_4',
        }),
      });
      expect(excluded.status).toBe(200);
      expect(getPath(excluded.json, 'result', 'counted')).toBe(false);
      expect(Number(getPath(excluded.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const duplicate = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_2',
          action: 'approve',
          succeeded: true,
          sourceEventId: 'usage_evt_3',
        }),
      });
      expect(duplicate.status).toBe(200);
      expect(getPath(duplicate.json, 'result', 'accepted')).toBe(false);
      expect(getPath(duplicate.json, 'result', 'counted')).toBe(false);
      expect(Number(getPath(duplicate.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const usage = await fetchJson(`${srv.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`, {
        method: 'GET',
      });
      expect(usage.status).toBe(200);
      expect(getPath(usage.json, 'usage', 'usageMetricVersion')).toBe('maw_v1');
      expect(getPath(usage.json, 'usage', 'monthUtc')).toBe(monthUtc);
      expect(Number(getPath(usage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(2);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/invoices/generate requires admin or ops role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          periodMonthUtc: '2026-01',
        }),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('invoice generation endpoint returns deterministic line items', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_1',
          action: 'transfer',
          succeeded: true,
          occurredAt: '2026-01-05T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_1',
        }),
      });
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_2',
          action: 'swap',
          succeeded: true,
          occurredAt: '2026-01-06T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_2',
        }),
      });
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_3',
          action: 'wallet_created',
          succeeded: true,
          occurredAt: '2026-01-07T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_3',
        }),
      });

      const generated = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ periodMonthUtc: '2026-01' }),
      });
      expect(generated.status).toBe(200);
      expect(getPath(generated.json, 'generation', 'generated')).toBe(true);
      expect(Number(getPath(generated.json, 'generation', 'invoice', 'amountDueMinor') || 0)).toBe(2500);
      const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
      expect(invoiceId).toBeTruthy();

      const lineItems = await fetchJson(`${srv.baseUrl}/console/billing/invoices/${encodeURIComponent(invoiceId)}/line-items`, {
        method: 'GET',
      });
      expect(lineItems.status).toBe(200);
      const items = Array.isArray(lineItems.json?.lineItems) ? lineItems.json?.lineItems : [];
      expect(items.length).toBe(2);
      expect(JSON.stringify(items)).toContain('"itemType":"PLAN_BASE_FEE"');
      expect(JSON.stringify(items)).toContain('"itemType":"MAW_USAGE"');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stablecoins/payment-intents/:id/reconcile requires admin or ops role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents/scpi_fake/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          observedAmountMinor: 1,
          observedConfirmations: 1,
        }),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('stablecoin reconcile transitions to confirming then settled and updates invoice', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId, quoteId }),
      });
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      const expectedAmountMinor = Number(getPath(created.json, 'paymentIntent', 'expectedAmountMinor') || 0);
      const requiredConfirmations = Number(getPath(created.json, 'paymentIntent', 'requiredConfirmations') || 0);
      expect(paymentIntentId).toBeTruthy();
      expect(expectedAmountMinor).toBeGreaterThan(0);
      expect(requiredConfirmations).toBeGreaterThan(0);

      const confirming = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          observedAmountMinor: expectedAmountMinor,
          observedConfirmations: Math.max(requiredConfirmations - 1, 0),
        }),
      });
      expect(confirming.status).toBe(200);
      expect(getPath(confirming.json, 'paymentIntent', 'state')).toBe('CONFIRMING');

      const settled = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          observedAmountMinor: expectedAmountMinor,
          observedConfirmations: requiredConfirmations,
        }),
      });
      expect(settled.status).toBe(200);
      expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');
      expect(getPath(settled.json, 'paymentIntent', 'settledAt')).toBeTruthy();
      expect(getPath(settled.json, 'paymentIntent', 'reorgRiskWindowEndsAt')).toBeTruthy();
      expect(getPath(settled.json, 'paymentIntent', 'withinReorgRiskWindow')).toBe(true);

      const invoice = await fetchJson(`${srv.baseUrl}/console/billing/invoices/${invoiceId}`, { method: 'GET' });
      expect(invoice.status).toBe(200);
      expect(getPath(invoice.json, 'invoice', 'status')).toBe('PAID');
      expect(Number(getPath(invoice.json, 'invoice', 'amountPaidMinor') || 0)).toBeGreaterThanOrEqual(expectedAmountMinor);
    } finally {
      await srv.close();
    }
  });

  test('stablecoin reconcile after intent expiry returns EXPIRED and leaves invoice open', async () => {
    let current = new Date('2026-03-01T00:00:00.000Z');
    const billing = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId, quoteId }),
      });
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      const expectedAmountMinor = Number(getPath(created.json, 'paymentIntent', 'expectedAmountMinor') || 0);
      const requiredConfirmations = Number(getPath(created.json, 'paymentIntent', 'requiredConfirmations') || 0);
      expect(paymentIntentId).toBeTruthy();
      expect(requiredConfirmations).toBeGreaterThan(0);

      current = new Date(current.getTime() + (16 * 60 * 1000));

      const reconcile = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          observedAmountMinor: expectedAmountMinor,
          observedConfirmations: requiredConfirmations,
        }),
      });
      expect(reconcile.status).toBe(200);
      expect(getPath(reconcile.json, 'paymentIntent', 'state')).toBe('EXPIRED');

      const invoice = await fetchJson(`${srv.baseUrl}/console/billing/invoices/${invoiceId}`, { method: 'GET' });
      expect(invoice.status).toBe(200);
      expect(getPath(invoice.json, 'invoice', 'status')).toBe('OPEN');
      expect(Number(getPath(invoice.json, 'invoice', 'amountPaidMinor') || 0)).toBe(0);
    } finally {
      await srv.close();
    }
  });

  test('stripe reconcile transitions action_required -> settled and updates invoice', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      expect(getPath(created.json, 'paymentIntent', 'state')).toBe('CREATED');
      const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
      expect(paymentIntentId).toBeTruthy();
      expect(amountMinor).toBeGreaterThan(0);

      const actionRequired = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerStatus: 'ACTION_REQUIRED',
          sourceEventId: `evt_${Date.now()}_action_required`,
        }),
      });
      expect(actionRequired.status).toBe(200);
      expect(getPath(actionRequired.json, 'paymentIntent', 'state')).toBe('ACTION_REQUIRED');

      const pending = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerStatus: 'PENDING',
          sourceEventId: `evt_${Date.now()}_pending`,
        }),
      });
      expect(pending.status).toBe(200);
      expect(getPath(pending.json, 'paymentIntent', 'state')).toBe('PENDING');

      const settled = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
          sourceEventId: `evt_${Date.now()}_succeeded`,
        }),
      });
      expect(settled.status).toBe(200);
      expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');

      const invoice = await fetchJson(`${srv.baseUrl}/console/billing/invoices/${invoiceId}`, { method: 'GET' });
      expect(invoice.status).toBe(200);
      expect(getPath(invoice.json, 'invoice', 'status')).toBe('PAID');
    } finally {
      await srv.close();
    }
  });

  test('billing transitions emit billing webhook events when webhook endpoint is configured', async () => {
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const endpointCreated = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/billing-events',
          subscriptions: ['billing'],
        }),
      });
      expect(endpointCreated.status).toBe(201);
      const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
      expect(invoiceId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
      expect(paymentIntentId).toBeTruthy();
      expect(amountMinor).toBeGreaterThan(0);

      const actionRequired = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerStatus: 'ACTION_REQUIRED',
        }),
      });
      expect(actionRequired.status).toBe(200);

      const pending = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerStatus: 'PENDING',
        }),
      });
      expect(pending.status).toBe(200);

      const settled = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
        }),
      });
      expect(settled.status).toBe(200);
      expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');

      const deliveries = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`, {
        method: 'GET',
      });
      expect(deliveries.status).toBe(200);
      const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
      const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
      expect(eventTypes).toContain('billing.payment_intent.created');
      expect(eventTypes).toContain('billing.payment_intent.updated');
      expect(eventTypes).toContain('billing.invoice.paid');

      const pageOne = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2`, {
        method: 'GET',
      });
      expect(pageOne.status).toBe(200);
      const pageOneRows = Array.isArray(pageOne.json?.deliveries) ? pageOne.json?.deliveries : [];
      expect(pageOneRows.length).toBe(2);
      const pageOneCursor = String(pageOne.json?.nextCursor || '');
      expect(pageOneCursor).toBeTruthy();

      const pageTwo = await fetchJson(`${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2&cursor=${encodeURIComponent(pageOneCursor)}`, {
        method: 'GET',
      });
      expect(pageTwo.status).toBe(200);
      const pageTwoRows = Array.isArray(pageTwo.json?.deliveries) ? pageTwo.json?.deliveries : [];
      expect(pageTwoRows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await srv.close();
    }
  });
});

test.describe('console router (cloudflare)', () => {
  test('GET /console/healthz works', async () => {
    const handler = createCloudflareConsoleRouter({ healthz: true });
    const res = await callCf(handler, { method: 'GET', path: '/console/healthz' });
    expect(res.status).toBe(200);
    expect(res.json?.service).toBe('console');
  });

  test('GET /console/webhooks returns webhooks_not_configured without webhook service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('webhooks_not_configured');
  });

  test('GET /console/api-keys returns api_keys_not_configured without API key service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('api_keys_not_configured');
  });

  test('cloudflare API key lifecycle works and secrets are reveal-once on create/rotate', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'cloudflare-key',
        environmentId: 'prod',
        scopes: ['wallets:read'],
        ipAllowlist: ['198.51.100.5/32'],
      },
    });
    expect(created.status).toBe(201);
    const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
    const createdSecret = String(getPath(created.json, 'secret') || '');
    expect(keyId).toBeTruthy();
    expect(createdSecret).toContain('tsk_');
    expect(Number(getPath(created.json, 'apiKey', 'secretVersion') || 0)).toBe(1);

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(listed.status).toBe(200);
    expect(String(getPath(listed.json, 'apiKeys', 0, 'id') || '')).toBe(keyId);
    expect(getPath(listed.json, 'apiKeys', 0, 'secret')).toBeUndefined();

    const rotated = await callCf(handler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
      body: {
        reason: 'manual rotate',
      },
    });
    expect(rotated.status).toBe(200);
    const rotatedSecret = String(getPath(rotated.json, 'secret') || '');
    expect(rotatedSecret).toContain('tsk_');
    expect(rotatedSecret).not.toBe(createdSecret);
    expect(Number(getPath(rotated.json, 'apiKey', 'secretVersion') || 0)).toBe(2);

    const revoked = await callCf(handler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(keyId)}`,
    });
    expect(revoked.status).toBe(200);
    expect(getPath(revoked.json, 'revoked')).toBe(true);
    expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');

    const rotateRevoked = await callCf(handler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
    });
    expect(rotateRevoked.status).toBe(409);
    expect(rotateRevoked.json?.code).toBe('api_key_revoked');
  });

  test('cloudflare webhook routes support delivery attempts, dead letters, and replay', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-webhook',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(listed.status).toBe(200);
    expect(Array.isArray(listed.json?.endpoints)).toBe(true);
    expect(String(getPath(listed.json, 'endpoints', 0, 'id') || '')).toBe(endpointId);

    const emitted = await webhooks.emitEvent({
      orgId: 'org-1',
      actorUserId: 'system-webhooks-test',
      roles: ['ops'],
    }, {
      eventType: 'billing.invoice.paid',
      payload: {
        invoiceId: 'inv_cf_1',
      },
    });
    expect(emitted.attempted).toBe(1);
    expect(emitted.delivered).toBe(0);
    expect(emitted.failed).toBe(1);

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
    expect(rows.length).toBe(1);
    expect(String(getPath(deliveries.json, 'deliveries', 0, 'status') || '')).toBe('FAILED');
    const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
    expect(deliveryId).toBeTruthy();

    const attemptsBeforeReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts`,
    });
    expect(attemptsBeforeReplay.status).toBe(200);
    expect(Number(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
    expect(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'status')).toBe('FAILED');

    const unresolvedDlq = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
    });
    expect(unresolvedDlq.status).toBe(200);
    const unresolvedRows = Array.isArray(unresolvedDlq.json?.deadLetters) ? unresolvedDlq.json?.deadLetters : [];
    expect(unresolvedRows.length).toBe(1);
    expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
    expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'resolvedAt')).toBeNull();

    const replayed = await callCf(handler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: { deliveryId },
    });
    expect(replayed.status).toBe(200);
    expect(getPath(replayed.json, 'replay', 'replayed')).toBe(true);
    expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');

    const attemptsAfterReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1`,
    });
    expect(attemptsAfterReplay.status).toBe(200);
    const replayAttempts = Array.isArray(attemptsAfterReplay.json?.attempts) ? attemptsAfterReplay.json?.attempts : [];
    expect(replayAttempts.length).toBe(1);
    expect(Number(getPath(attemptsAfterReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(2);
    expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'isReplay')).toBe(true);
    const attemptsNextCursor = String(attemptsAfterReplay.json?.nextCursor || '');
    expect(attemptsNextCursor).toBeTruthy();

    const attemptsSecondPage = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1&cursor=${encodeURIComponent(attemptsNextCursor)}`,
    });
    expect(attemptsSecondPage.status).toBe(200);
    const replayAttemptsSecondPage = Array.isArray(attemptsSecondPage.json?.attempts)
      ? attemptsSecondPage.json?.attempts
      : [];
    expect(replayAttemptsSecondPage.length).toBe(1);
    expect(Number(getPath(attemptsSecondPage.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
    expect(String(attemptsSecondPage.json?.nextCursor || '')).toBe('');

    const unresolvedAfterReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
    });
    expect(unresolvedAfterReplay.status).toBe(200);
    const unresolvedRowsAfterReplay = Array.isArray(unresolvedAfterReplay.json?.deadLetters)
      ? unresolvedAfterReplay.json?.deadLetters
      : [];
    expect(unresolvedRowsAfterReplay.length).toBe(0);

    const resolvedDlq = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?includeResolved=true`,
    });
    expect(resolvedDlq.status).toBe(200);
    const resolvedRows = Array.isArray(resolvedDlq.json?.deadLetters) ? resolvedDlq.json?.deadLetters : [];
    expect(resolvedRows.length).toBe(1);
    expect(getPath(resolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
    expect(Boolean(getPath(resolvedDlq.json, 'deadLetters', 0, 'resolvedAt'))).toBe(true);

    const updated = await callCf(handler, {
      method: 'PATCH',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
      body: {
        status: 'DISABLED',
      },
    });
    expect(updated.status).toBe(200);
    expect(getPath(updated.json, 'endpoint', 'status')).toBe('DISABLED');

    const deleted = await callCf(handler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(deleted.status).toBe(200);
    expect(deleted.json?.removed).toBe(true);
  });

  test('cloudflare webhook list endpoints reject malformed cursor', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks: createInMemoryConsoleWebhookService(),
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/bad-cursor-cloudflare',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=bad_cursor`,
    });
    expect(deliveries.status).toBe(400);
    expect(deliveries.json?.code).toBe('invalid_query');

    const attempts = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=bad_cursor`,
    });
    expect(attempts.status).toBe(400);
    expect(attempts.json?.code).toBe('invalid_query');

    const deadLetters = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?cursor=bad_cursor`,
    });
    expect(deadLetters.status).toBe(400);
    expect(deadLetters.json?.code).toBe('invalid_query');

    const oversizedSortKey = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=9007199254740992%3Aoverflow`,
    });
    expect(oversizedSortKey.status).toBe(400);
    expect(oversizedSortKey.json?.code).toBe('invalid_query');
  });

  test('GET /console/billing/stablecoins/assets requires auth adapter', async () => {
    const handler = createCloudflareConsoleRouter({});
    const res = await callCf(handler, { method: 'GET', path: '/console/billing/stablecoins/assets' });
    expect(res.status).toBe(503);
    expect(res.json?.code).toBe('console_auth_not_configured');
  });

  test('GET /console/billing/stablecoins/assets returns supported assets/chains', async () => {
    const handler = createCloudflareConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const res = await callCf(handler, { method: 'GET', path: '/console/billing/stablecoins/assets' });
    expect(res.status).toBe(200);
    expect(res.json?.version).toBe('v1');
    expect(JSON.stringify(res.json?.assets || null)).toContain('"asset":"USDT"');
    expect(JSON.stringify(res.json?.assets || null)).toContain('"chain":"NEAR"');
    expect(JSON.stringify(res.json?.assets || null)).toContain('"requiredConfirmations":10');
  });

  test('POST /console/billing/payment-methods requires admin role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/payment-methods',
      body: {},
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('POST /console/billing/stripe/webhook requires configured shared secret', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      body: {
        eventId: 'evt_cf_missing_secret',
        providerRef: 'pi_provider_missing',
        providerStatus: 'SUCCEEDED',
      },
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('stripe_webhook_not_configured');
  });

  test('POST /console/billing/invoices/generate requires admin or ops role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-01',
      },
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('billing flow: stablecoin intent locks rail from stripe card intent', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDT',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const intent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId,
        quoteId,
      },
    });
    expect(intent.status).toBe(201);
    expect(getPath(intent.json, 'paymentIntent', 'rail')).toBe('STABLECOIN');

    const stripeIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: {
        invoiceId,
      },
    });
    expect(stripeIntent.status).toBe(409);
    expect(stripeIntent.json?.code).toBe('invoice_rail_locked');
  });

  test('stablecoin quote is single-use across payment intents', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDT',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const firstIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: { invoiceId, quoteId },
    });
    expect(firstIntent.status).toBe(201);
    const paymentIntentId = String(getPath(firstIntent.json, 'paymentIntent', 'id') || '');
    expect(paymentIntentId).toBeTruthy();

    const canceled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(paymentIntentId)}/cancel`,
    });
    expect(canceled.status).toBe(200);
    expect(getPath(canceled.json, 'paymentIntent', 'state')).toBe('CANCELED');

    const reused = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: { invoiceId, quoteId },
    });
    expect(reused.status).toBe(409);
    expect(reused.json?.code).toBe('quote_already_consumed');
  });

  test('stripe payment intents reject concurrent active attempts', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const firstIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(firstIntent.status).toBe(201);
    expect(getPath(firstIntent.json, 'paymentIntent', 'state')).toBe('CREATED');

    const secondIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(secondIntent.status).toBe(409);
    expect(secondIntent.json?.code).toBe('active_payment_intent_exists');
  });

  test('Stripe webhook reconciles payment intent by providerRef and dedupes event id', async () => {
    const billing = createInMemoryConsoleBillingService();
    const secret = 'whsec_console_router_cf_test';
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      billingStripeWebhookSecret: secret,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(created.status).toBe(201);
    const providerRef = String(getPath(created.json, 'paymentIntent', 'providerRef') || '');
    const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
    expect(providerRef).toBeTruthy();
    expect(amountMinor).toBeGreaterThan(0);

    const unauthorized = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      body: {
        eventId: 'evt_cf_webhook_unauthorized',
        providerRef,
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.json?.code).toBe('unauthorized');

    const eventId = `evt_cf_webhook_${Date.now()}`;
    const first = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId,
        providerRef,
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(first.status).toBe(200);
    expect(first.json?.accepted).toBe(true);
    expect(getPath(first.json, 'paymentIntent', 'state')).toBe('SETTLED');

    const duplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId,
        providerRef,
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(duplicate.status).toBe(200);
    expect(duplicate.json?.accepted).toBe(false);
    expect(getPath(duplicate.json, 'paymentIntent', 'state')).toBe('SETTLED');
  });

  test('billing usage endpoints compute MAW with exclusions and idempotency', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const e1 = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_1',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_1',
      },
    });
    expect(e1.status).toBe(200);
    expect(getPath(e1.json, 'result', 'accepted')).toBe(true);
    expect(getPath(e1.json, 'result', 'counted')).toBe(true);
    expect(Number(getPath(e1.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);
    const monthUtc = String(getPath(e1.json, 'result', 'monthUtc') || '');
    expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

    const e2 = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_2',
        action: 'swap',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_2',
      },
    });
    expect(e2.status).toBe(200);
    expect(Number(getPath(e2.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const excluded = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_3',
        action: 'wallet_created',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_3',
      },
    });
    expect(excluded.status).toBe(200);
    expect(getPath(excluded.json, 'result', 'counted')).toBe(false);
    expect(Number(getPath(excluded.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const duplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_2',
        action: 'swap',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_2',
      },
    });
    expect(duplicate.status).toBe(200);
    expect(getPath(duplicate.json, 'result', 'accepted')).toBe(false);
    expect(Number(getPath(duplicate.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const usage = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(usage.status).toBe(200);
    expect(getPath(usage.json, 'usage', 'monthUtc')).toBe(monthUtc);
    expect(Number(getPath(usage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(2);
  });

  test('invoice generation endpoint returns deterministic line items', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_gen_1',
        action: 'transfer',
        succeeded: true,
        occurredAt: '2026-01-05T01:00:00.000Z',
        sourceEventId: 'router_cf_gen_evt_1',
      },
    });
    await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_gen_2',
        action: 'swap',
        succeeded: true,
        occurredAt: '2026-01-06T01:00:00.000Z',
        sourceEventId: 'router_cf_gen_evt_2',
      },
    });

    const generated = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-01',
      },
    });
    expect(generated.status).toBe(200);
    expect(getPath(generated.json, 'generation', 'generated')).toBe(true);
    expect(Number(getPath(generated.json, 'generation', 'invoice', 'amountDueMinor') || 0)).toBe(2500);
    const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
    expect(invoiceId).toBeTruthy();

    const lineItems = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(invoiceId)}/line-items`,
    });
    expect(lineItems.status).toBe(200);
    const items = Array.isArray(lineItems.json?.lineItems) ? lineItems.json?.lineItems : [];
    expect(items.length).toBe(2);
    expect(JSON.stringify(items)).toContain('"itemType":"PLAN_BASE_FEE"');
    expect(JSON.stringify(items)).toContain('"itemType":"MAW_USAGE"');
  });

  test('POST /console/billing/stablecoins/payment-intents/:id/reconcile requires admin or ops role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents/scpi_fake/reconcile',
      body: {
        observedAmountMinor: 1,
        observedConfirmations: 1,
      },
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('stablecoin reconcile timeout moves intent to failed', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDT',
        chain: 'Base',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId,
        quoteId,
      },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    expect(paymentIntentId).toBeTruthy();

    const reconciled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        observedAmountMinor: 0,
        observedConfirmations: 0,
        confirmationTimedOut: true,
      },
    });
    expect(reconciled.status).toBe(200);
    expect(getPath(reconciled.json, 'paymentIntent', 'state')).toBe('FAILED');
  });

  test('stablecoin reconcile after intent expiry returns EXPIRED and leaves invoice open', async () => {
    let current = new Date('2026-03-01T00:00:00.000Z');
    const billing = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDC',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId,
        quoteId,
      },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    const expectedAmountMinor = Number(getPath(created.json, 'paymentIntent', 'expectedAmountMinor') || 0);
    const requiredConfirmations = Number(getPath(created.json, 'paymentIntent', 'requiredConfirmations') || 0);
    expect(paymentIntentId).toBeTruthy();
    expect(requiredConfirmations).toBeGreaterThan(0);

    current = new Date(current.getTime() + (16 * 60 * 1000));

    const reconciled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        observedAmountMinor: expectedAmountMinor,
        observedConfirmations: requiredConfirmations,
      },
    });
    expect(reconciled.status).toBe(200);
    expect(getPath(reconciled.json, 'paymentIntent', 'state')).toBe('EXPIRED');

    const invoice = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(invoiceId)}`,
    });
    expect(invoice.status).toBe(200);
    expect(getPath(invoice.json, 'invoice', 'status')).toBe('OPEN');
    expect(Number(getPath(invoice.json, 'invoice', 'amountPaidMinor') || 0)).toBe(0);
  });

  test('stripe reconcile settles payment intent', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    expect(getPath(created.json, 'paymentIntent', 'state')).toBe('CREATED');
    const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
    expect(paymentIntentId).toBeTruthy();
    expect(amountMinor).toBeGreaterThan(0);

    const pending = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'PENDING',
        sourceEventId: `evt_${Date.now()}_cf_pending`,
      },
    });
    expect(pending.status).toBe(200);
    expect(getPath(pending.json, 'paymentIntent', 'state')).toBe('PENDING');

    const settled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
        sourceEventId: `evt_${Date.now()}_cf_succeeded`,
      },
    });
    expect(settled.status).toBe(200);
    expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');
  });

  test('cloudflare billing transitions emit billing webhook events', async () => {
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      webhooks,
    });

    const endpointCreated = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-billing-events',
        subscriptions: ['billing'],
      },
    });
    expect(endpointCreated.status).toBe(201);
    const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices) ? (invoices.json?.invoices?.[0] as any)?.id : '';
    expect(invoiceId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
    expect(paymentIntentId).toBeTruthy();
    expect(amountMinor).toBeGreaterThan(0);

    const actionRequired = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'ACTION_REQUIRED',
      },
    });
    expect(actionRequired.status).toBe(200);

    const pending = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'PENDING',
      },
    });
    expect(pending.status).toBe(200);

    const settled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(settled.status).toBe(200);
    expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
    const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
    expect(eventTypes).toContain('billing.payment_intent.created');
    expect(eventTypes).toContain('billing.payment_intent.updated');
    expect(eventTypes).toContain('billing.invoice.paid');

    const pageOne = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2`,
    });
    expect(pageOne.status).toBe(200);
    const pageOneRows = Array.isArray(pageOne.json?.deliveries) ? pageOne.json?.deliveries : [];
    expect(pageOneRows.length).toBe(2);
    const pageOneCursor = String(pageOne.json?.nextCursor || '');
    expect(pageOneCursor).toBeTruthy();

    const pageTwo = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2&cursor=${encodeURIComponent(pageOneCursor)}`,
    });
    expect(pageTwo.status).toBe(200);
    const pageTwoRows = Array.isArray(pageTwo.json?.deliveries) ? pageTwo.json?.deliveries : [];
    expect(pageTwoRows.length).toBeGreaterThanOrEqual(1);
  });
});

test.describe('console router (postgres webhooks)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:webhooks:postgres');
  const authOrgId = 'org-router-postgres-webhooks';
  let webhooks: ConsoleWebhookService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    webhooks = await createPostgresConsoleWebhookService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_webhook_attempts WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_dead_letters WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_deliveries WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_endpoints WHERE namespace = $1', [namespace]);
  });

  test('express attempts list rejects non-numeric attempt cursor id', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], authOrgId, 'ops-router-postgres'),
      webhooks: webhooks!,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/postgres-router-bad-attempt-cursor-express',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const cursor = `${Date.parse('2026-01-03T00:00:00.000Z')}:non_numeric_attempt_id`;
      const attempts = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(cursor)}`,
        {
          method: 'GET',
        },
      );
      expect(attempts.status).toBe(400);
      expect(attempts.json?.code).toBe('invalid_query');

      const oversizedSortCursor = '9007199254740992:attempt_1';
      const oversizedSortKey = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(oversizedSortCursor)}`,
        {
          method: 'GET',
        },
      );
      expect(oversizedSortKey.status).toBe(400);
      expect(oversizedSortKey.json?.code).toBe('invalid_query');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare attempts list rejects non-numeric attempt cursor id', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], authOrgId, 'ops-router-postgres'),
      webhooks: webhooks!,
    });
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/postgres-router-bad-attempt-cursor-cloudflare',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const cursor = `${Date.parse('2026-01-03T00:00:00.000Z')}:non_numeric_attempt_id`;
    const attempts = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(cursor)}`,
    });
    expect(attempts.status).toBe(400);
    expect(attempts.json?.code).toBe('invalid_query');

    const oversizedSortCursor = '9007199254740992:attempt_1';
    const oversizedSortKey = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(oversizedSortCursor)}`,
    });
    expect(oversizedSortKey.status).toBe(400);
    expect(oversizedSortKey.json?.code).toBe('invalid_query');
  });

  test('express webhook routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-user'),
      webhooks: webhooks!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let endpointId = '';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/postgres-router-org-isolation-express-owner',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-user'),
      webhooks: webhooks!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(list.status).toBe(200);
      const attackerEndpoints = Array.isArray(list.json?.endpoints) ? list.json?.endpoints : [];
      expect(attackerEndpoints.some((entry: any) => String(entry?.id || '') === endpointId)).toBe(false);

      const deliveries = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        { method: 'GET' },
      );
      expect(deliveries.status).toBe(404);
      expect(deliveries.json?.code).toBe('webhook_not_found');

      const replay = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        },
      );
      expect(replay.status).toBe(404);
      expect(replay.json?.code).toBe('webhook_not_found');

      const deleted = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        { method: 'DELETE' },
      );
      expect(deleted.status).toBe(404);
      expect(deleted.json?.code).toBe('webhook_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare webhook routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-user-cf'),
      webhooks: webhooks!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/postgres-router-org-isolation-cloudflare-owner',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-user-cf'),
      webhooks: webhooks!,
    });
    const list = await callCf(attackerHandler, { method: 'GET', path: '/console/webhooks' });
    expect(list.status).toBe(200);
    const attackerEndpoints = Array.isArray(list.json?.endpoints) ? list.json?.endpoints : [];
    expect(attackerEndpoints.some((entry: any) => String(entry?.id || '') === endpointId)).toBe(false);

    const deliveries = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(404);
    expect(deliveries.json?.code).toBe('webhook_not_found');

    const replay = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: {},
    });
    expect(replay.status).toBe(404);
    expect(replay.json?.code).toBe('webhook_not_found');

    const deleted = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(deleted.status).toBe(404);
    expect(deleted.json?.code).toBe('webhook_not_found');
  });
});

test.describe('console router (postgres billing)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:billing:postgres');
  const authOrgId = 'org-router-postgres-billing';
  let billing: ConsoleBillingService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    billing = await createPostgresConsoleBillingService({
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

  test('express billing routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-billing-user'),
      billing: billing!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerInvoiceId = '';
    try {
      const invoices = await fetchJson(`${ownerServer.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      ownerInvoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      expect(ownerInvoiceId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-billing-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(list.status).toBe(200);
      const attackerInvoices = Array.isArray(list.json?.invoices) ? list.json?.invoices : [];
      expect(attackerInvoices.some((entry: any) => String(entry?.id || '') === ownerInvoiceId)).toBe(false);

      const getInvoice = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}`,
        { method: 'GET' },
      );
      expect(getInvoice.status).toBe(404);
      expect(getInvoice.json?.code).toBe('invoice_not_found');

      const getLineItems = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/line-items`,
        { method: 'GET' },
      );
      expect(getLineItems.status).toBe(404);
      expect(getLineItems.json?.code).toBe('invoice_not_found');

      const stripeIntent = await fetchJson(`${attackerServer.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId: ownerInvoiceId }),
      });
      expect(stripeIntent.status).toBe(404);
      expect(stripeIntent.json?.code).toBe('invoice_not_found');

      const quote = await fetchJson(`${attackerServer.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId: ownerInvoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(404);
      expect(quote.json?.code).toBe('invoice_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-billing-user-cf'),
      billing: billing!,
    });
    const ownerInvoices = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(ownerInvoices.status).toBe(200);
    const ownerInvoiceId = String(getPath(ownerInvoices.json, 'invoices', 0, 'id') || '');
    expect(ownerInvoiceId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-billing-user-cf'),
      billing: billing!,
    });
    const list = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(list.status).toBe(200);
    const attackerInvoices = Array.isArray(list.json?.invoices) ? list.json?.invoices : [];
    expect(attackerInvoices.some((entry: any) => String(entry?.id || '') === ownerInvoiceId)).toBe(false);

    const getInvoice = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}`,
    });
    expect(getInvoice.status).toBe(404);
    expect(getInvoice.json?.code).toBe('invoice_not_found');

    const getLineItems = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/line-items`,
    });
    expect(getLineItems.status).toBe(404);
    expect(getLineItems.json?.code).toBe('invoice_not_found');

    const stripeIntent = await callCf(attackerHandler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId: ownerInvoiceId },
    });
    expect(stripeIntent.status).toBe(404);
    expect(stripeIntent.json?.code).toBe('invoice_not_found');

    const quote = await callCf(attackerHandler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId: ownerInvoiceId,
        asset: 'USDC',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(404);
    expect(quote.json?.code).toBe('invoice_not_found');
  });

  test('express billing payment-intent routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCardOrgId = `${authOrgId}:owner-card`;
    const ownerStableOrgId = `${authOrgId}:owner-stable`;
    const attackerOrgId = `${authOrgId}:attacker-intents`;

    let stripeIntentId = '';
    const ownerCardRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerCardOrgId, 'owner-card-user'),
      billing: billing!,
    });
    const ownerCardServer = await startExpressRouter(ownerCardRouter);
    try {
      const invoices = await fetchJson(`${ownerCardServer.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      expect(invoiceId).toBeTruthy();

      const stripeIntent = await fetchJson(`${ownerCardServer.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(stripeIntent.status).toBe(201);
      stripeIntentId = String(getPath(stripeIntent.json, 'paymentIntent', 'id') || '');
      expect(stripeIntentId).toBeTruthy();
    } finally {
      await ownerCardServer.close();
    }

    let stableIntentId = '';
    const ownerStableRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerStableOrgId, 'owner-stable-user'),
      billing: billing!,
    });
    const ownerStableServer = await startExpressRouter(ownerStableRouter);
    try {
      const invoices = await fetchJson(`${ownerStableServer.baseUrl}/console/billing/invoices`, { method: 'GET' });
      expect(invoices.status).toBe(200);
      const invoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${ownerStableServer.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const stableIntent = await fetchJson(`${ownerStableServer.baseUrl}/console/billing/stablecoins/payment-intents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          quoteId,
        }),
      });
      expect(stableIntent.status).toBe(201);
      stableIntentId = String(getPath(stableIntent.json, 'paymentIntent', 'id') || '');
      expect(stableIntentId).toBeTruthy();
    } finally {
      await ownerStableServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-intents-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const stripeReconcile = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stripe/payment-intents/${encodeURIComponent(stripeIntentId)}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ providerStatus: 'PENDING' }),
        },
      );
      expect(stripeReconcile.status).toBe(404);
      expect(stripeReconcile.json?.code).toBe('payment_intent_not_found');

      const stableGet = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}`,
        { method: 'GET' },
      );
      expect(stableGet.status).toBe(404);
      expect(stableGet.json?.code).toBe('payment_intent_not_found');

      const stableCancel = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/cancel`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        },
      );
      expect(stableCancel.status).toBe(404);
      expect(stableCancel.json?.code).toBe('payment_intent_not_found');

      const stableReconcile = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            observedAmountMinor: 0,
            observedConfirmations: 0,
          }),
        },
      );
      expect(stableReconcile.status).toBe(404);
      expect(stableReconcile.json?.code).toBe('payment_intent_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing payment-intent routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCardOrgId = `${authOrgId}:owner-card-cf`;
    const ownerStableOrgId = `${authOrgId}:owner-stable-cf`;
    const attackerOrgId = `${authOrgId}:attacker-intents-cf`;

    const ownerCardHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerCardOrgId, 'owner-card-user-cf'),
      billing: billing!,
    });
    const ownerCardInvoices = await callCf(ownerCardHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(ownerCardInvoices.status).toBe(200);
    const ownerCardInvoiceId = String(getPath(ownerCardInvoices.json, 'invoices', 0, 'id') || '');
    expect(ownerCardInvoiceId).toBeTruthy();

    const ownerStripeIntent = await callCf(ownerCardHandler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId: ownerCardInvoiceId },
    });
    expect(ownerStripeIntent.status).toBe(201);
    const stripeIntentId = String(getPath(ownerStripeIntent.json, 'paymentIntent', 'id') || '');
    expect(stripeIntentId).toBeTruthy();

    const ownerStableHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerStableOrgId, 'owner-stable-user-cf'),
      billing: billing!,
    });
    const ownerStableInvoices = await callCf(ownerStableHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(ownerStableInvoices.status).toBe(200);
    const ownerStableInvoiceId = String(getPath(ownerStableInvoices.json, 'invoices', 0, 'id') || '');
    expect(ownerStableInvoiceId).toBeTruthy();

    const ownerQuote = await callCf(ownerStableHandler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId: ownerStableInvoiceId,
        asset: 'USDC',
        chain: 'Ethereum',
      },
    });
    expect(ownerQuote.status).toBe(201);
    const quoteId = String(getPath(ownerQuote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const ownerStableIntent = await callCf(ownerStableHandler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId: ownerStableInvoiceId,
        quoteId,
      },
    });
    expect(ownerStableIntent.status).toBe(201);
    const stableIntentId = String(getPath(ownerStableIntent.json, 'paymentIntent', 'id') || '');
    expect(stableIntentId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-intents-user-cf'),
      billing: billing!,
    });
    const stripeReconcile = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(stripeIntentId)}/reconcile`,
      body: {
        providerStatus: 'PENDING',
      },
    });
    expect(stripeReconcile.status).toBe(404);
    expect(stripeReconcile.json?.code).toBe('payment_intent_not_found');

    const stableGet = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}`,
    });
    expect(stableGet.status).toBe(404);
    expect(stableGet.json?.code).toBe('payment_intent_not_found');

    const stableCancel = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/cancel`,
      body: {},
    });
    expect(stableCancel.status).toBe(404);
    expect(stableCancel.json?.code).toBe('payment_intent_not_found');

    const stableReconcile = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/reconcile`,
      body: {
        observedAmountMinor: 0,
        observedConfirmations: 0,
      },
    });
    expect(stableReconcile.status).toBe(404);
    expect(stableReconcile.json?.code).toBe('payment_intent_not_found');
  });

  test('express billing overview and MAW usage routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-usage`;
    const attackerOrgId = `${authOrgId}:attacker-usage`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-usage-user'),
      billing: billing!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let monthUtc = '';
    try {
      const event = await fetchJson(`${ownerServer.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_owner_usage_1',
          action: 'transfer',
          succeeded: true,
          sourceEventId: `owner_usage_evt_${Date.now()}`,
        }),
      });
      expect(event.status).toBe(200);
      monthUtc = String(getPath(event.json, 'result', 'monthUtc') || '');
      expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

      const ownerOverview = await fetchJson(`${ownerServer.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(ownerOverview.status).toBe(200);
      expect(Number(getPath(ownerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(1);

      const ownerUsage = await fetchJson(
        `${ownerServer.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        { method: 'GET' },
      );
      expect(ownerUsage.status).toBe(200);
      expect(Number(getPath(ownerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-usage-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const attackerOverview = await fetchJson(`${attackerServer.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(attackerOverview.status).toBe(200);
      expect(Number(getPath(attackerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(0);

      const attackerUsage = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        { method: 'GET' },
      );
      expect(attackerUsage.status).toBe(200);
      expect(Number(getPath(attackerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(0);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing overview and MAW usage routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-usage-cf`;
    const attackerOrgId = `${authOrgId}:attacker-usage-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-usage-user-cf'),
      billing: billing!,
    });
    const event = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_owner_usage_cf_1',
        action: 'swap',
        succeeded: true,
        sourceEventId: `owner_usage_cf_evt_${Date.now()}`,
      },
    });
    expect(event.status).toBe(200);
    const monthUtc = String(getPath(event.json, 'result', 'monthUtc') || '');
    expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

    const ownerOverview = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(ownerOverview.status).toBe(200);
    expect(Number(getPath(ownerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(1);

    const ownerUsage = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(ownerUsage.status).toBe(200);
    expect(Number(getPath(ownerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-usage-user-cf'),
      billing: billing!,
    });
    const attackerOverview = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(attackerOverview.status).toBe(200);
    expect(Number(getPath(attackerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(0);

    const attackerUsage = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(attackerUsage.status).toBe(200);
    expect(Number(getPath(attackerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(0);
  });
});

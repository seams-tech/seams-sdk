import type { Request, Response, Router as ExpressRouter } from 'express';
import express from 'express';
import { buildCorsOrigins } from '../../core/SessionService';
import {
  CHAIN_FINALITY_POLICY_VERSION,
  isConsoleBillingError,
  listStablecoinAssetSupport,
  parseAddCardPaymentMethodRequest,
  parseBillingUsageEventRequest,
  parseGenerateMonthlyInvoiceRequest,
  parseStablecoinPaymentIntentReconcileRequest,
  parseStablecoinPaymentIntentRequest,
  parseStablecoinQuoteRequest,
  parseStripePaymentIntentReconcileRequest,
  parseStripePaymentIntentRequest,
  parseStripeWebhookEventRequest,
  parseStripeSetupIntentRequest,
  type ConsoleBillingService,
} from '../../console/billing';
import {
  isConsoleApiKeyError,
  parseCreateConsoleApiKeyRequest,
  parseRotateConsoleApiKeyRequest,
  type ConsoleApiKeyService,
} from '../../console/apiKeys';
import {
  isConsoleWebhookError,
  parseCreateConsoleWebhookEndpointRequest,
  parseListConsoleWebhookDeliveriesRequest,
  parseListConsoleWebhookAttemptsRequest,
  parseListConsoleWebhookDeadLettersRequest,
  parseReplayConsoleWebhookDeliveryRequest,
  parseUpdateConsoleWebhookEndpointRequest,
  type ConsoleWebhookService,
} from '../../console/webhooks';
import type {
  ConsoleAuthClaims,
  ConsoleAuthResult,
  ConsoleRouterOptions,
} from '../console';
import {
  authenticateConsoleRequest,
  hasConsoleRole,
} from '../console';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';

export interface ExpressConsoleContext {
  opts: ConsoleRouterOptions;
  logger: NormalizedRouterLogger;
  billing: ConsoleBillingService | null;
  apiKeys: ConsoleApiKeyService | null;
  webhooks: ConsoleWebhookService | null;
}

function withConsoleCors(res: Response, opts?: ConsoleRouterOptions, req?: Request): void {
  if (!opts?.corsOrigins) return;

  let allowedOrigin: string | '*' | undefined;
  const normalized = buildCorsOrigins(...(opts.corsOrigins || []));
  if (normalized === '*') {
    allowedOrigin = '*';
    res.set('Access-Control-Allow-Origin', '*');
  } else if (Array.isArray(normalized)) {
    const origin = String((req as any)?.headers?.origin || '').trim();
    if (origin && normalized.includes(origin)) {
      allowedOrigin = origin;
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
    }
  }

  res.set('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Console-Stripe-Webhook-Secret');
  if (allowedOrigin && allowedOrigin !== '*') {
    res.set('Access-Control-Allow-Credentials', 'true');
  }
}

function installConsoleCors(router: ExpressRouter, opts: ConsoleRouterOptions): void {
  router.use((req: Request, res: Response, next: any) => {
    withConsoleCors(res, opts, req);
    const method = String((req as any)?.method || '').toUpperCase();
    if (opts.corsOrigins && method === 'OPTIONS') {
      res.status(204).send('');
      return;
    }
    next();
  });
}

function sendAuthFailure(res: Response, auth: Extract<ConsoleAuthResult, { ok: false }>): void {
  res.status(auth.status).json({
    ok: false,
    code: auth.code,
    message: auth.message,
  });
}

function sendBillingError(res: Response, error: unknown): void {
  if (isConsoleBillingError(error)) {
    res.status(error.status).json({
      ok: false,
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    });
    return;
  }

  res.status(500).json({
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
  });
}

function sendApiKeyError(res: Response, error: unknown): void {
  if (isConsoleApiKeyError(error)) {
    res.status(error.status).json({
      ok: false,
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    });
    return;
  }

  res.status(500).json({
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
  });
}

function sendWebhookError(res: Response, error: unknown): void {
  if (isConsoleWebhookError(error)) {
    res.status(error.status).json({
      ok: false,
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    });
    return;
  }

  res.status(500).json({
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
  });
}

async function requireConsoleAuth(req: Request, res: Response, ctx: ExpressConsoleContext): Promise<ConsoleAuthClaims | null> {
  const auth = await authenticateConsoleRequest(req.headers as Record<string, string | string[] | undefined>, ctx.opts.auth);
  if (!auth.ok) {
    sendAuthFailure(res, auth);
    return null;
  }
  return auth.claims;
}

function requireBillingService(res: Response, ctx: ExpressConsoleContext): ConsoleBillingService | null {
  if (ctx.billing) return ctx.billing;
  res.status(501).json({
    ok: false,
    code: 'billing_not_configured',
    message: 'Billing service is not configured on this server',
  });
  return null;
}

function requireApiKeyService(res: Response, ctx: ExpressConsoleContext): ConsoleApiKeyService | null {
  if (ctx.apiKeys) return ctx.apiKeys;
  res.status(501).json({
    ok: false,
    code: 'api_keys_not_configured',
    message: 'API key service is not configured on this server',
  });
  return null;
}

function requireWebhookService(res: Response, ctx: ExpressConsoleContext): ConsoleWebhookService | null {
  if (ctx.webhooks) return ctx.webhooks;
  res.status(501).json({
    ok: false,
    code: 'webhooks_not_configured',
    message: 'Webhook service is not configured on this server',
  });
  return null;
}

function requireStripeWebhookSecret(req: Request, res: Response, ctx: ExpressConsoleContext): boolean {
  const configured = String(ctx.opts.billingStripeWebhookSecret || '').trim();
  if (!configured) {
    res.status(501).json({
      ok: false,
      code: 'stripe_webhook_not_configured',
      message: 'Stripe webhook secret is not configured on this server',
    });
    return false;
  }
  const raw = (req as any)?.headers?.['x-console-stripe-webhook-secret'];
  const provided = Array.isArray(raw) ? String(raw[0] || '').trim() : String(raw || '').trim();
  if (!provided || provided !== configured) {
    res.status(401).json({
      ok: false,
      code: 'unauthorized',
      message: 'Invalid Stripe webhook secret',
    });
    return false;
  }
  return true;
}

function toBillingContext(claims: ConsoleAuthClaims): {
  orgId: string;
  actorUserId: string;
  roles: string[];
} {
  return {
    orgId: claims.orgId,
    actorUserId: claims.userId,
    roles: claims.roles,
  };
}

function readPathParam(req: Request, key: string): string {
  return String((req as any)?.params?.[key] || '').trim();
}

function requireAdminRoleForCardActions(claims: ConsoleAuthClaims, res: Response): boolean {
  if (hasConsoleRole(claims, 'admin')) return true;
  res.status(403).json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin can add, remove, or set default card payment methods',
  });
  return false;
}

function requirePaymentReconcileRole(claims: ConsoleAuthClaims, res: Response): boolean {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'ops')) return true;
  res.status(403).json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin or ops can reconcile payment intents',
  });
  return false;
}

function requireInvoiceGenerationRole(claims: ConsoleAuthClaims, res: Response): boolean {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'ops')) return true;
  res.status(403).json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin or ops can generate monthly invoices',
  });
  return false;
}

const BILLING_TERMINAL_SETTLEMENT_STATES = new Set([
  'SETTLED',
  'PARTIALLY_SETTLED',
  'OVERPAID',
]);

async function emitBillingWebhookEvent(
  ctx: ExpressConsoleContext,
  input: {
    orgId: string;
    actorUserId: string;
    eventType: string;
    payload: Record<string, unknown>;
    eventId?: string;
  },
): Promise<void> {
  if (!ctx.webhooks) return;
  try {
    await ctx.webhooks.emitEvent(
      {
        orgId: input.orgId,
        actorUserId: input.actorUserId,
        roles: ['ops'],
      },
      {
        eventId: input.eventId,
        eventType: input.eventType,
        payload: input.payload,
      },
    );
  } catch (error: unknown) {
    ctx.logger.warn('[console][webhooks] failed to emit billing event', {
      eventType: input.eventType,
      orgId: input.orgId,
      message: error instanceof Error ? error.message : String(error),
    });
  }
}

async function emitInvoicePaidWebhookIfApplicable(
  ctx: ExpressConsoleContext,
  billing: ConsoleBillingService,
  input: {
    orgId: string;
    actorUserId: string;
    roles: string[];
    invoiceId: string;
    paymentIntentId: string;
    rail: 'CARD' | 'STABLECOIN';
  },
): Promise<void> {
  try {
    const invoice = await billing.getInvoice(
      {
        orgId: input.orgId,
        actorUserId: input.actorUserId,
        roles: input.roles,
      },
      input.invoiceId,
    );
    if (!invoice || invoice.status !== 'PAID') return;

    await emitBillingWebhookEvent(ctx, {
      orgId: input.orgId,
      actorUserId: input.actorUserId,
      eventType: 'billing.invoice.paid',
      payload: {
        invoiceId: invoice.id,
        status: invoice.status,
        amountDueMinor: invoice.amountDueMinor,
        amountPaidMinor: invoice.amountPaidMinor,
        railLock: invoice.railLock,
        paymentIntentId: input.paymentIntentId,
        paymentRail: input.rail,
      },
    });
  } catch (error: unknown) {
    ctx.logger.warn('[console][webhooks] failed to inspect invoice after payment update', {
      invoiceId: input.invoiceId,
      orgId: input.orgId,
      message: error instanceof Error ? error.message : String(error),
    });
  }
}

function registerConsoleHealthRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  if (ctx.opts.healthz) {
    router.get('/console/healthz', async (_req: Request, res: Response) => {
      res.status(200).json({
        ok: true,
        service: 'console',
      });
    });
  }

  if (ctx.opts.readyz) {
    router.get('/console/readyz', async (_req: Request, res: Response) => {
      try {
        if (ctx.opts.readyCheck) {
          await ctx.opts.readyCheck();
        }
        res.status(200).json({
          ok: true,
          service: 'console',
        });
      } catch (error: unknown) {
        res.status(503).json({
          ok: false,
          code: 'console_not_ready',
          message: error instanceof Error ? error.message : String(error),
        });
      }
    });
  }
}

function registerConsoleSessionRoute(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/session', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    res.status(200).json({
      ok: true,
      claims,
    });
  });
}

function registerConsoleApiKeyRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/api-keys', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    try {
      const out = await apiKeys.listApiKeys(toBillingContext(claims));
      res.status(200).json({ ok: true, apiKeys: out });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });

  router.post('/console/api-keys', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    try {
      const request = parseCreateConsoleApiKeyRequest((req as any).body);
      const created = await apiKeys.createApiKey(toBillingContext(claims), request);
      res.status(201).json({
        ok: true,
        apiKey: created.apiKey,
        secret: created.secret,
      });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });

  router.delete('/console/api-keys/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    const apiKeyId = readPathParam(req, 'id');
    if (!apiKeyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing API key id' });
      return;
    }
    try {
      const revoked = await apiKeys.revokeApiKey(toBillingContext(claims), apiKeyId);
      if (!revoked.revoked || !revoked.apiKey) {
        res.status(404).json({
          ok: false,
          code: 'api_key_not_found',
          message: `API key ${apiKeyId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, revoked: true, apiKey: revoked.apiKey });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });

  router.post('/console/api-keys/:id/rotate', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    const apiKeyId = readPathParam(req, 'id');
    if (!apiKeyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing API key id' });
      return;
    }
    try {
      const request = parseRotateConsoleApiKeyRequest((req as any).body);
      const rotated = await apiKeys.rotateApiKey(toBillingContext(claims), apiKeyId, request);
      if (!rotated) {
        res.status(404).json({
          ok: false,
          code: 'api_key_not_found',
          message: `API key ${apiKeyId} was not found`,
        });
        return;
      }
      res.status(200).json({
        ok: true,
        apiKey: rotated.apiKey,
        secret: rotated.secret,
      });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });
}

function registerConsoleWebhookRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/webhooks', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    try {
      const endpoints = await webhooks.listEndpoints(toBillingContext(claims));
      res.status(200).json({ ok: true, endpoints });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.post('/console/webhooks', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    try {
      const request = parseCreateConsoleWebhookEndpointRequest((req as any).body);
      const endpoint = await webhooks.createEndpoint(toBillingContext(claims), request);
      res.status(201).json({ ok: true, endpoint });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.patch('/console/webhooks/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    const endpointId = readPathParam(req, 'id');
    if (!endpointId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
      return;
    }
    try {
      const request = parseUpdateConsoleWebhookEndpointRequest((req as any).body);
      const endpoint = await webhooks.updateEndpoint(toBillingContext(claims), endpointId, request);
      if (!endpoint) {
        res.status(404).json({
          ok: false,
          code: 'webhook_not_found',
          message: `Webhook endpoint ${endpointId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, endpoint });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.delete('/console/webhooks/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    const endpointId = readPathParam(req, 'id');
    if (!endpointId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
      return;
    }
    try {
      const out = await webhooks.deleteEndpoint(toBillingContext(claims), endpointId);
      if (!out.removed) {
        res.status(404).json({
          ok: false,
          code: 'webhook_not_found',
          message: `Webhook endpoint ${endpointId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, removed: true });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.get('/console/webhooks/:id/deliveries', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    const endpointId = readPathParam(req, 'id');
    if (!endpointId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
      return;
    }
    try {
      const request = parseListConsoleWebhookDeliveriesRequest((req as any).query || {});
      const page = await webhooks.listDeliveries(toBillingContext(claims), endpointId, request);
      res.status(200).json({
        ok: true,
        deliveries: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.get('/console/webhooks/:id/attempts', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    const endpointId = readPathParam(req, 'id');
    if (!endpointId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
      return;
    }
    try {
      const request = parseListConsoleWebhookAttemptsRequest((req as any).query || {});
      const page = await webhooks.listAttempts(toBillingContext(claims), endpointId, request);
      res.status(200).json({
        ok: true,
        attempts: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.get('/console/webhooks/:id/dead-letters', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    const endpointId = readPathParam(req, 'id');
    if (!endpointId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
      return;
    }
    try {
      const request = parseListConsoleWebhookDeadLettersRequest((req as any).query || {});
      const page = await webhooks.listDeadLetters(toBillingContext(claims), endpointId, request);
      res.status(200).json({
        ok: true,
        deadLetters: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.post('/console/webhooks/:id/replay', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    const endpointId = readPathParam(req, 'id');
    if (!endpointId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
      return;
    }
    try {
      const request = parseReplayConsoleWebhookDeliveryRequest((req as any).body);
      const replay = await webhooks.replayDelivery(toBillingContext(claims), endpointId, request);
      if (!replay.replayed) {
        if (replay.reason === 'endpoint_not_found') {
          res.status(404).json({
            ok: false,
            code: 'webhook_not_found',
            message: `Webhook endpoint ${endpointId} was not found`,
          });
          return;
        }
        if (replay.reason === 'delivery_not_found') {
          res.status(404).json({
            ok: false,
            code: 'delivery_not_found',
            message: `Webhook delivery ${request.deliveryId} was not found`,
          });
          return;
        }
        res.status(409).json({
          ok: false,
          code: 'no_replayable_delivery',
          message: 'No replayable delivery exists for this endpoint',
        });
        return;
      }
      res.status(200).json({ ok: true, replay });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });
}

function registerConsoleBillingRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.post('/console/billing/stripe/webhook', async (req: Request, res: Response) => {
    if (!requireStripeWebhookSecret(req, res, ctx)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseStripeWebhookEventRequest((req as any).body);
      const result = await billing.processStripeWebhookEvent(request);
      if (result.accepted && result.paymentIntent && result.orgId) {
        await emitBillingWebhookEvent(ctx, {
          orgId: result.orgId,
          actorUserId: 'system-stripe-webhook',
          eventType: 'billing.payment_intent.updated',
          eventId: request.eventId,
          payload: {
            paymentIntentId: result.paymentIntent.id,
            invoiceId: result.paymentIntent.invoiceId,
            providerRef: result.paymentIntent.providerRef,
            state: result.paymentIntent.state,
            rail: result.paymentIntent.rail,
            source: 'stripe_webhook',
          },
        });
      }
      res.status(200).json({ ok: true, ...result });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/overview', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const overview = await billing.getOverview(toBillingContext(claims));
      res.status(200).json({ ok: true, overview });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/usage/monthly-active-wallets', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const monthUtcRaw = String((req as any)?.query?.monthUtc || '').trim();
    const monthUtc = monthUtcRaw || undefined;
    try {
      const usage = await billing.getMonthlyActiveWallets(toBillingContext(claims), monthUtc);
      res.status(200).json({ ok: true, usage });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/usage/events', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseBillingUsageEventRequest((req as any).body);
      const result = await billing.recordUsageEvent(toBillingContext(claims), request);
      res.status(200).json({ ok: true, result });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/invoices/generate', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireInvoiceGenerationRole(claims, res)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseGenerateMonthlyInvoiceRequest((req as any).body);
      const generation = await billing.generateMonthlyInvoice(toBillingContext(claims), request);
      await emitBillingWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'billing.invoice.generated',
        payload: {
          invoiceId: generation.invoice.id,
          periodMonthUtc: generation.invoice.periodMonthUtc,
          generated: generation.generated,
          monthlyActiveWallets: generation.monthlyActiveWallets,
          amountDueMinor: generation.invoice.amountDueMinor,
          lineItemCount: generation.lineItems.length,
        },
      });
      res.status(200).json({ ok: true, generation });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/invoices', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const invoices = await billing.listInvoices(toBillingContext(claims));
      res.status(200).json({ ok: true, invoices });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/invoices/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const invoiceId = readPathParam(req, 'id');
    if (!invoiceId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing invoice id' });
      return;
    }
    try {
      const invoice = await billing.getInvoice(toBillingContext(claims), invoiceId);
      if (!invoice) {
        res.status(404).json({ ok: false, code: 'invoice_not_found', message: `Invoice ${invoiceId} was not found` });
        return;
      }
      res.status(200).json({ ok: true, invoice });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/invoices/:id/line-items', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const invoiceId = readPathParam(req, 'id');
    if (!invoiceId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing invoice id' });
      return;
    }
    try {
      const invoice = await billing.getInvoice(toBillingContext(claims), invoiceId);
      if (!invoice) {
        res.status(404).json({ ok: false, code: 'invoice_not_found', message: `Invoice ${invoiceId} was not found` });
        return;
      }
      const lineItems = await billing.listInvoiceLineItems(toBillingContext(claims), invoiceId);
      res.status(200).json({ ok: true, lineItems });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/payment-methods', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const paymentMethods = await billing.listPaymentMethods(toBillingContext(claims));
      res.status(200).json({ ok: true, paymentMethods });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/payment-methods', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireAdminRoleForCardActions(claims, res)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseAddCardPaymentMethodRequest((req as any).body);
      const paymentMethod = await billing.addCardPaymentMethod(toBillingContext(claims), request);
      res.status(201).json({ ok: true, paymentMethod });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.delete('/console/billing/payment-methods/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireAdminRoleForCardActions(claims, res)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const paymentMethodId = readPathParam(req, 'id');
    if (!paymentMethodId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing payment method id' });
      return;
    }
    try {
      const out = await billing.removeCardPaymentMethod(toBillingContext(claims), paymentMethodId);
      if (!out.removed) {
        res.status(404).json({ ok: false, code: 'payment_method_not_found', message: `Payment method ${paymentMethodId} was not found` });
        return;
      }
      res.status(200).json({ ok: true, removed: true });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/payment-methods/:id/default', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireAdminRoleForCardActions(claims, res)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const paymentMethodId = readPathParam(req, 'id');
    if (!paymentMethodId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing payment method id' });
      return;
    }
    try {
      const paymentMethod = await billing.setDefaultCardPaymentMethod(toBillingContext(claims), paymentMethodId);
      if (!paymentMethod) {
        res.status(404).json({ ok: false, code: 'payment_method_not_found', message: `Payment method ${paymentMethodId} was not found` });
        return;
      }
      res.status(200).json({ ok: true, paymentMethod });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/stripe/setup-intent', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseStripeSetupIntentRequest((req as any).body);
      const setupIntent = await billing.createStripeSetupIntent(toBillingContext(claims), request);
      res.status(200).json({ ok: true, setupIntent });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/stripe/payment-intent', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseStripePaymentIntentRequest((req as any).body);
      const paymentIntent = await billing.createStripePaymentIntent(toBillingContext(claims), request);
      await emitBillingWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'billing.payment_intent.created',
        payload: {
          paymentIntentId: paymentIntent.id,
          invoiceId: paymentIntent.invoiceId,
          rail: paymentIntent.rail,
          state: paymentIntent.state,
          amountMinor: paymentIntent.amountMinor,
        },
      });
      res.status(201).json({ ok: true, paymentIntent });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/stripe/payment-intents/:id/reconcile', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requirePaymentReconcileRole(claims, res)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const paymentIntentId = readPathParam(req, 'id');
    if (!paymentIntentId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
      return;
    }
    try {
      const request = parseStripePaymentIntentReconcileRequest((req as any).body);
      const paymentIntent = await billing.reconcileStripePaymentIntent(
        toBillingContext(claims),
        paymentIntentId,
        request,
      );
      if (!paymentIntent) {
        res.status(404).json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stripe payment intent ${paymentIntentId} was not found`,
        });
        return;
      }
      await emitBillingWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'billing.payment_intent.updated',
        payload: {
          paymentIntentId: paymentIntent.id,
          invoiceId: paymentIntent.invoiceId,
          providerRef: paymentIntent.providerRef,
          state: paymentIntent.state,
          rail: paymentIntent.rail,
          source: 'manual_reconcile',
        },
      });
      if (BILLING_TERMINAL_SETTLEMENT_STATES.has(paymentIntent.state)) {
        await emitInvoicePaidWebhookIfApplicable(ctx, billing, {
          orgId: claims.orgId,
          actorUserId: claims.userId,
          roles: claims.roles,
          invoiceId: paymentIntent.invoiceId,
          paymentIntentId: paymentIntent.id,
          rail: 'CARD',
        });
      }
      res.status(200).json({ ok: true, paymentIntent });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/stablecoins/assets', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    res.status(200).json({
      ok: true,
      version: CHAIN_FINALITY_POLICY_VERSION,
      assets: listStablecoinAssetSupport(),
    });
  });

  router.post('/console/billing/stablecoins/quotes', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseStablecoinQuoteRequest((req as any).body);
      const quote = await billing.createStablecoinQuote(toBillingContext(claims), request);
      res.status(201).json({ ok: true, quote });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/stablecoins/payment-intents', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseStablecoinPaymentIntentRequest((req as any).body);
      const paymentIntent = await billing.createStablecoinPaymentIntent(toBillingContext(claims), request);
      await emitBillingWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'billing.payment_intent.created',
        payload: {
          paymentIntentId: paymentIntent.id,
          invoiceId: paymentIntent.invoiceId,
          rail: paymentIntent.rail,
          state: paymentIntent.state,
          expectedAmountMinor: paymentIntent.expectedAmountMinor,
          asset: paymentIntent.asset,
          chain: paymentIntent.chain,
        },
      });
      res.status(201).json({ ok: true, paymentIntent });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/stablecoins/payment-intents/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const paymentIntentId = readPathParam(req, 'id');
    if (!paymentIntentId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
      return;
    }
    try {
      const paymentIntent = await billing.getStablecoinPaymentIntent(toBillingContext(claims), paymentIntentId);
      if (!paymentIntent) {
        res.status(404).json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stablecoin payment intent ${paymentIntentId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, paymentIntent });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/stablecoins/payment-intents/:id/cancel', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const paymentIntentId = readPathParam(req, 'id');
    if (!paymentIntentId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
      return;
    }
    try {
      const paymentIntent = await billing.cancelStablecoinPaymentIntent(toBillingContext(claims), paymentIntentId);
      if (!paymentIntent) {
        res.status(404).json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stablecoin payment intent ${paymentIntentId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, paymentIntent });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/stablecoins/payment-intents/:id/reconcile', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requirePaymentReconcileRole(claims, res)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const paymentIntentId = readPathParam(req, 'id');
    if (!paymentIntentId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
      return;
    }
    try {
      const request = parseStablecoinPaymentIntentReconcileRequest((req as any).body);
      const paymentIntent = await billing.reconcileStablecoinPaymentIntent(
        toBillingContext(claims),
        paymentIntentId,
        request,
      );
      if (!paymentIntent) {
        res.status(404).json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stablecoin payment intent ${paymentIntentId} was not found`,
        });
        return;
      }
      await emitBillingWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'billing.payment_intent.updated',
        payload: {
          paymentIntentId: paymentIntent.id,
          invoiceId: paymentIntent.invoiceId,
          state: paymentIntent.state,
          rail: paymentIntent.rail,
          asset: paymentIntent.asset,
          chain: paymentIntent.chain,
          source: 'manual_reconcile',
        },
      });
      if (BILLING_TERMINAL_SETTLEMENT_STATES.has(paymentIntent.state)) {
        await emitInvoicePaidWebhookIfApplicable(ctx, billing, {
          orgId: claims.orgId,
          actorUserId: claims.userId,
          roles: claims.roles,
          invoiceId: paymentIntent.invoiceId,
          paymentIntentId: paymentIntent.id,
          rail: 'STABLECOIN',
        });
      }
      res.status(200).json({ ok: true, paymentIntent });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });
}

export function createConsoleRouter(opts: ConsoleRouterOptions = {}): ExpressRouter {
  const router = express.Router();
  const logger = coerceRouterLogger(opts.logger);
  const billing = opts.billing === undefined ? null : opts.billing;
  const apiKeys = opts.apiKeys === undefined ? null : opts.apiKeys;
  const webhooks = opts.webhooks === undefined ? null : opts.webhooks;

  installConsoleCors(router, opts);

  const ctx: ExpressConsoleContext = {
    opts,
    logger,
    billing,
    apiKeys,
    webhooks,
  };

  registerConsoleHealthRoutes(router, ctx);
  registerConsoleSessionRoute(router, ctx);
  registerConsoleApiKeyRoutes(router, ctx);
  registerConsoleWebhookRoutes(router, ctx);
  registerConsoleBillingRoutes(router, ctx);

  return router;
}

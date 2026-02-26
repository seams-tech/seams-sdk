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
import type { CfEnv, CfExecutionContext, FetchHandler } from './types';
import { headersToRecord, json, readJson } from './http';

export interface CloudflareConsoleContext {
  request: Request;
  url: URL;
  pathname: string;
  method: string;
  env?: CfEnv;
  cfCtx?: CfExecutionContext;

  opts: ConsoleRouterOptions;
  logger: NormalizedRouterLogger;
  billing: ConsoleBillingService | null;
  apiKeys: ConsoleApiKeyService | null;
  webhooks: ConsoleWebhookService | null;
}

function withConsoleCors(headers: Headers, opts?: ConsoleRouterOptions, request?: Request): void {
  if (!opts?.corsOrigins) return;

  let allowedOrigin: string | '*' | undefined;
  const normalized = buildCorsOrigins(...(opts.corsOrigins || []));
  if (normalized === '*') {
    allowedOrigin = '*';
    headers.set('Access-Control-Allow-Origin', '*');
  } else if (Array.isArray(normalized)) {
    const origin = request?.headers.get('Origin') || '';
    if (origin && normalized.includes(origin)) {
      allowedOrigin = origin;
      headers.set('Access-Control-Allow-Origin', origin);
      headers.append('Vary', 'Origin');
    }
  }

  headers.set('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Console-Stripe-Webhook-Secret');
  if (allowedOrigin && allowedOrigin !== '*') {
    headers.set('Access-Control-Allow-Credentials', 'true');
  }
}

function sendAuthFailure(auth: Extract<ConsoleAuthResult, { ok: false }>): Response {
  return json({
    ok: false,
    code: auth.code,
    message: auth.message,
  }, { status: auth.status });
}

function sendBillingError(error: unknown): Response {
  if (isConsoleBillingError(error)) {
    return json({
      ok: false,
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    }, { status: error.status });
  }

  return json({
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
  }, { status: 500 });
}

function sendApiKeyError(error: unknown): Response {
  if (isConsoleApiKeyError(error)) {
    return json({
      ok: false,
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    }, { status: error.status });
  }

  return json({
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
  }, { status: 500 });
}

function sendWebhookError(error: unknown): Response {
  if (isConsoleWebhookError(error)) {
    return json({
      ok: false,
      code: error.code,
      message: error.message,
      ...(error.details ? { details: error.details } : {}),
    }, { status: error.status });
  }

  return json({
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
  }, { status: 500 });
}

async function requireConsoleAuth(
  ctx: CloudflareConsoleContext,
): Promise<{ ok: true; claims: ConsoleAuthClaims } | { ok: false; response: Response }> {
  const auth = await authenticateConsoleRequest(headersToRecord(ctx.request.headers), ctx.opts.auth);
  if (!auth.ok) {
    return { ok: false, response: sendAuthFailure(auth) };
  }
  return { ok: true, claims: auth.claims };
}

function requireBillingService(ctx: CloudflareConsoleContext): ConsoleBillingService | Response {
  if (ctx.billing) return ctx.billing;
  return json({
    ok: false,
    code: 'billing_not_configured',
    message: 'Billing service is not configured on this server',
  }, { status: 501 });
}

function requireApiKeyService(ctx: CloudflareConsoleContext): ConsoleApiKeyService | Response {
  if (ctx.apiKeys) return ctx.apiKeys;
  return json({
    ok: false,
    code: 'api_keys_not_configured',
    message: 'API key service is not configured on this server',
  }, { status: 501 });
}

function requireWebhookService(ctx: CloudflareConsoleContext): ConsoleWebhookService | Response {
  if (ctx.webhooks) return ctx.webhooks;
  return json({
    ok: false,
    code: 'webhooks_not_configured',
    message: 'Webhook service is not configured on this server',
  }, { status: 501 });
}

function requireStripeWebhookSecret(ctx: CloudflareConsoleContext): Response | null {
  const configured = String(ctx.opts.billingStripeWebhookSecret || '').trim();
  if (!configured) {
    return json({
      ok: false,
      code: 'stripe_webhook_not_configured',
      message: 'Stripe webhook secret is not configured on this server',
    }, { status: 501 });
  }
  const provided = String(ctx.request.headers.get('x-console-stripe-webhook-secret') || '').trim();
  if (!provided || provided !== configured) {
    return json({
      ok: false,
      code: 'unauthorized',
      message: 'Invalid Stripe webhook secret',
    }, { status: 401 });
  }
  return null;
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

function requireAdminRoleForCardActions(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin')) return null;
  return json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin can add, remove, or set default card payment methods',
  }, { status: 403 });
}

function requirePaymentReconcileRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'ops')) return null;
  return json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin or ops can reconcile payment intents',
  }, { status: 403 });
}

function requireInvoiceGenerationRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'ops')) return null;
  return json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin or ops can generate monthly invoices',
  }, { status: 403 });
}

const BILLING_TERMINAL_SETTLEMENT_STATES = new Set([
  'SETTLED',
  'PARTIALLY_SETTLED',
  'OVERPAID',
]);

async function emitBillingWebhookEvent(
  ctx: CloudflareConsoleContext,
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
  ctx: CloudflareConsoleContext,
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

function decodePathPart(part: string): string {
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
}

async function handleConsoleHealth(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!ctx.opts.healthz || ctx.method !== 'GET' || ctx.pathname !== '/console/healthz') return null;

  return json({
    ok: true,
    service: 'console',
  }, { status: 200 });
}

async function handleConsoleReady(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!ctx.opts.readyz || ctx.method !== 'GET' || ctx.pathname !== '/console/readyz') return null;
  try {
    if (ctx.opts.readyCheck) {
      await ctx.opts.readyCheck();
    }
    return json({
      ok: true,
      service: 'console',
    }, { status: 200 });
  } catch (error: unknown) {
    return json({
      ok: false,
      code: 'console_not_ready',
      message: error instanceof Error ? error.message : String(error),
    }, { status: 503 });
  }
}

async function handleConsoleSession(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (ctx.method !== 'GET' || ctx.pathname !== '/console/session') return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  return json({
    ok: true,
    claims: auth.claims,
  }, { status: 200 });
}

function isConsoleBillingPath(pathname: string): boolean {
  return pathname.startsWith('/console/billing/');
}

function isConsoleApiKeyPath(pathname: string): boolean {
  return pathname.startsWith('/console/api-keys');
}

function isConsoleWebhookPath(pathname: string): boolean {
  return pathname.startsWith('/console/webhooks');
}

async function handleConsoleApiKeys(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleApiKeyPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const apiKeysOrResponse = requireApiKeyService(ctx);
  if (apiKeysOrResponse instanceof Response) return apiKeysOrResponse;
  const apiKeys = apiKeysOrResponse;
  const apiKeyCtx = toBillingContext(auth.claims);

  const apiKeyPathMatch = ctx.pathname.match(/^\/console\/api-keys\/([^/]+)$/);
  const apiKeyRotatePathMatch = ctx.pathname.match(/^\/console\/api-keys\/([^/]+)\/rotate$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/api-keys') {
      const out = await apiKeys.listApiKeys(apiKeyCtx);
      return json({ ok: true, apiKeys: out }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/api-keys') {
      const request = parseCreateConsoleApiKeyRequest(await readJson(ctx.request));
      const created = await apiKeys.createApiKey(apiKeyCtx, request);
      return json({
        ok: true,
        apiKey: created.apiKey,
        secret: created.secret,
      }, { status: 201 });
    }

    if (ctx.method === 'DELETE' && apiKeyPathMatch) {
      const apiKeyId = decodePathPart(apiKeyPathMatch[1]);
      const revoked = await apiKeys.revokeApiKey(apiKeyCtx, apiKeyId);
      if (!revoked.revoked || !revoked.apiKey) {
        return json({
          ok: false,
          code: 'api_key_not_found',
          message: `API key ${apiKeyId} was not found`,
        }, { status: 404 });
      }
      return json({
        ok: true,
        revoked: true,
        apiKey: revoked.apiKey,
      }, { status: 200 });
    }

    if (ctx.method === 'POST' && apiKeyRotatePathMatch) {
      const apiKeyId = decodePathPart(apiKeyRotatePathMatch[1]);
      const request = parseRotateConsoleApiKeyRequest(await readJson(ctx.request));
      const rotated = await apiKeys.rotateApiKey(apiKeyCtx, apiKeyId, request);
      if (!rotated) {
        return json({
          ok: false,
          code: 'api_key_not_found',
          message: `API key ${apiKeyId} was not found`,
        }, { status: 404 });
      }
      return json({
        ok: true,
        apiKey: rotated.apiKey,
        secret: rotated.secret,
      }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendApiKeyError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleWebhooks(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleWebhookPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const webhooksOrResponse = requireWebhookService(ctx);
  if (webhooksOrResponse instanceof Response) return webhooksOrResponse;
  const webhooks = webhooksOrResponse;
  const webhookCtx = toBillingContext(auth.claims);

  const endpointMatch = ctx.pathname.match(/^\/console\/webhooks\/([^/]+)$/);
  const deliveriesMatch = ctx.pathname.match(/^\/console\/webhooks\/([^/]+)\/deliveries$/);
  const attemptsMatch = ctx.pathname.match(/^\/console\/webhooks\/([^/]+)\/attempts$/);
  const deadLettersMatch = ctx.pathname.match(/^\/console\/webhooks\/([^/]+)\/dead-letters$/);
  const replayMatch = ctx.pathname.match(/^\/console\/webhooks\/([^/]+)\/replay$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/webhooks') {
      const endpoints = await webhooks.listEndpoints(webhookCtx);
      return json({ ok: true, endpoints }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/webhooks') {
      const request = parseCreateConsoleWebhookEndpointRequest(await readJson(ctx.request));
      const endpoint = await webhooks.createEndpoint(webhookCtx, request);
      return json({ ok: true, endpoint }, { status: 201 });
    }

    if (ctx.method === 'PATCH' && endpointMatch) {
      const endpointId = decodePathPart(endpointMatch[1]);
      const request = parseUpdateConsoleWebhookEndpointRequest(await readJson(ctx.request));
      const endpoint = await webhooks.updateEndpoint(webhookCtx, endpointId, request);
      if (!endpoint) {
        return json({
          ok: false,
          code: 'webhook_not_found',
          message: `Webhook endpoint ${endpointId} was not found`,
        }, { status: 404 });
      }
      return json({ ok: true, endpoint }, { status: 200 });
    }

    if (ctx.method === 'DELETE' && endpointMatch) {
      const endpointId = decodePathPart(endpointMatch[1]);
      const out = await webhooks.deleteEndpoint(webhookCtx, endpointId);
      if (!out.removed) {
        return json({
          ok: false,
          code: 'webhook_not_found',
          message: `Webhook endpoint ${endpointId} was not found`,
        }, { status: 404 });
      }
      return json({ ok: true, removed: true }, { status: 200 });
    }

    if (ctx.method === 'GET' && deliveriesMatch) {
      const endpointId = decodePathPart(deliveriesMatch[1]);
      const request = parseListConsoleWebhookDeliveriesRequest({
        limit: ctx.url.searchParams.get('limit') || undefined,
        cursor: ctx.url.searchParams.get('cursor') || undefined,
      });
      const page = await webhooks.listDeliveries(webhookCtx, endpointId, request);
      return json({
        ok: true,
        deliveries: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      }, { status: 200 });
    }

    if (ctx.method === 'GET' && attemptsMatch) {
      const endpointId = decodePathPart(attemptsMatch[1]);
      const request = parseListConsoleWebhookAttemptsRequest({
        deliveryId: ctx.url.searchParams.get('deliveryId') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
        cursor: ctx.url.searchParams.get('cursor') || undefined,
      });
      const page = await webhooks.listAttempts(webhookCtx, endpointId, request);
      return json({
        ok: true,
        attempts: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      }, { status: 200 });
    }

    if (ctx.method === 'GET' && deadLettersMatch) {
      const endpointId = decodePathPart(deadLettersMatch[1]);
      const includeResolvedRaw = ctx.url.searchParams.get('includeResolved');
      const request = parseListConsoleWebhookDeadLettersRequest({
        deliveryId: ctx.url.searchParams.get('deliveryId') || undefined,
        includeResolved: includeResolvedRaw === null ? undefined : includeResolvedRaw,
        limit: ctx.url.searchParams.get('limit') || undefined,
        cursor: ctx.url.searchParams.get('cursor') || undefined,
      });
      const page = await webhooks.listDeadLetters(webhookCtx, endpointId, request);
      return json({
        ok: true,
        deadLetters: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      }, { status: 200 });
    }

    if (ctx.method === 'POST' && replayMatch) {
      const endpointId = decodePathPart(replayMatch[1]);
      const request = parseReplayConsoleWebhookDeliveryRequest(await readJson(ctx.request));
      const replay = await webhooks.replayDelivery(webhookCtx, endpointId, request);
      if (!replay.replayed) {
        if (replay.reason === 'endpoint_not_found') {
          return json({
            ok: false,
            code: 'webhook_not_found',
            message: `Webhook endpoint ${endpointId} was not found`,
          }, { status: 404 });
        }
        if (replay.reason === 'delivery_not_found') {
          return json({
            ok: false,
            code: 'delivery_not_found',
            message: `Webhook delivery ${request.deliveryId} was not found`,
          }, { status: 404 });
        }
        return json({
          ok: false,
          code: 'no_replayable_delivery',
          message: 'No replayable delivery exists for this endpoint',
        }, { status: 409 });
      }
      return json({ ok: true, replay }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendWebhookError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleBilling(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleBillingPath(ctx.pathname)) return null;

  if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stripe/webhook') {
    const secretRequired = requireStripeWebhookSecret(ctx);
    if (secretRequired) return secretRequired;
    const billingOrResponse = requireBillingService(ctx);
    if (billingOrResponse instanceof Response) return billingOrResponse;
    try {
      const request = parseStripeWebhookEventRequest(await readJson(ctx.request));
      const result = await billingOrResponse.processStripeWebhookEvent(request);
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
      return json({ ok: true, ...result }, { status: 200 });
    } catch (error: unknown) {
      return sendBillingError(error);
    }
  }

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const invoiceMatch = ctx.pathname.match(/^\/console\/billing\/invoices\/([^/]+)$/);
  const invoiceLineItemsMatch = ctx.pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/line-items$/);
  const paymentMethodMatch = ctx.pathname.match(/^\/console\/billing\/payment-methods\/([^/]+)$/);
  const paymentMethodDefaultMatch = ctx.pathname.match(/^\/console\/billing\/payment-methods\/([^/]+)\/default$/);
  const stripeIntentReconcileMatch = ctx.pathname.match(/^\/console\/billing\/stripe\/payment-intents\/([^/]+)\/reconcile$/);
  const stablecoinIntentMatch = ctx.pathname.match(/^\/console\/billing\/stablecoins\/payment-intents\/([^/]+)$/);
  const stablecoinIntentCancelMatch = ctx.pathname.match(/^\/console\/billing\/stablecoins\/payment-intents\/([^/]+)\/cancel$/);
  const stablecoinIntentReconcileMatch = ctx.pathname.match(/^\/console\/billing\/stablecoins\/payment-intents\/([^/]+)\/reconcile$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/billing/stablecoins/assets') {
      return json({
        ok: true,
        version: CHAIN_FINALITY_POLICY_VERSION,
        assets: listStablecoinAssetSupport(),
      }, { status: 200 });
    }

    const billingOrResponse = requireBillingService(ctx);
    if (billingOrResponse instanceof Response) return billingOrResponse;
    const billing = billingOrResponse;
    const billingCtx = toBillingContext(auth.claims);

    if (ctx.method === 'GET' && ctx.pathname === '/console/billing/overview') {
      const overview = await billing.getOverview(billingCtx);
      return json({ ok: true, overview }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/billing/usage/monthly-active-wallets') {
      const monthUtcRaw = String(ctx.url.searchParams.get('monthUtc') || '').trim();
      const monthUtc = monthUtcRaw || undefined;
      const usage = await billing.getMonthlyActiveWallets(billingCtx, monthUtc);
      return json({ ok: true, usage }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/usage/events') {
      const request = parseBillingUsageEventRequest(await readJson(ctx.request));
      const result = await billing.recordUsageEvent(billingCtx, request);
      return json({ ok: true, result }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/invoices/generate') {
      const roleRequired = requireInvoiceGenerationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parseGenerateMonthlyInvoiceRequest(await readJson(ctx.request));
      const generation = await billing.generateMonthlyInvoice(billingCtx, request);
      await emitBillingWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
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
      return json({ ok: true, generation }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/billing/invoices') {
      const invoices = await billing.listInvoices(billingCtx);
      return json({ ok: true, invoices }, { status: 200 });
    }

    if (ctx.method === 'GET' && invoiceMatch) {
      const invoiceId = decodePathPart(invoiceMatch[1]);
      const invoice = await billing.getInvoice(billingCtx, invoiceId);
      if (!invoice) {
        return json({
          ok: false,
          code: 'invoice_not_found',
          message: `Invoice ${invoiceId} was not found`,
        }, { status: 404 });
      }
      return json({ ok: true, invoice }, { status: 200 });
    }

    if (ctx.method === 'GET' && invoiceLineItemsMatch) {
      const invoiceId = decodePathPart(invoiceLineItemsMatch[1]);
      const invoice = await billing.getInvoice(billingCtx, invoiceId);
      if (!invoice) {
        return json({
          ok: false,
          code: 'invoice_not_found',
          message: `Invoice ${invoiceId} was not found`,
        }, { status: 404 });
      }
      const lineItems = await billing.listInvoiceLineItems(billingCtx, invoiceId);
      return json({ ok: true, lineItems }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/billing/payment-methods') {
      const paymentMethods = await billing.listPaymentMethods(billingCtx);
      return json({ ok: true, paymentMethods }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/payment-methods') {
      const adminRequired = requireAdminRoleForCardActions(auth.claims);
      if (adminRequired) return adminRequired;
      const request = parseAddCardPaymentMethodRequest(await readJson(ctx.request));
      const paymentMethod = await billing.addCardPaymentMethod(billingCtx, request);
      return json({ ok: true, paymentMethod }, { status: 201 });
    }

    if (ctx.method === 'DELETE' && paymentMethodMatch) {
      const adminRequired = requireAdminRoleForCardActions(auth.claims);
      if (adminRequired) return adminRequired;
      const paymentMethodId = decodePathPart(paymentMethodMatch[1]);
      const out = await billing.removeCardPaymentMethod(billingCtx, paymentMethodId);
      if (!out.removed) {
        return json({
          ok: false,
          code: 'payment_method_not_found',
          message: `Payment method ${paymentMethodId} was not found`,
        }, { status: 404 });
      }
      return json({ ok: true, removed: true }, { status: 200 });
    }

    if (ctx.method === 'POST' && paymentMethodDefaultMatch) {
      const adminRequired = requireAdminRoleForCardActions(auth.claims);
      if (adminRequired) return adminRequired;
      const paymentMethodId = decodePathPart(paymentMethodDefaultMatch[1]);
      const paymentMethod = await billing.setDefaultCardPaymentMethod(billingCtx, paymentMethodId);
      if (!paymentMethod) {
        return json({
          ok: false,
          code: 'payment_method_not_found',
          message: `Payment method ${paymentMethodId} was not found`,
        }, { status: 404 });
      }
      return json({ ok: true, paymentMethod }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stripe/setup-intent') {
      const request = parseStripeSetupIntentRequest(await readJson(ctx.request));
      const setupIntent = await billing.createStripeSetupIntent(billingCtx, request);
      return json({ ok: true, setupIntent }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stripe/payment-intent') {
      const request = parseStripePaymentIntentRequest(await readJson(ctx.request));
      const paymentIntent = await billing.createStripePaymentIntent(billingCtx, request);
      await emitBillingWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
        eventType: 'billing.payment_intent.created',
        payload: {
          paymentIntentId: paymentIntent.id,
          invoiceId: paymentIntent.invoiceId,
          rail: paymentIntent.rail,
          state: paymentIntent.state,
          amountMinor: paymentIntent.amountMinor,
        },
      });
      return json({ ok: true, paymentIntent }, { status: 201 });
    }

    if (ctx.method === 'POST' && stripeIntentReconcileMatch) {
      const roleRequired = requirePaymentReconcileRole(auth.claims);
      if (roleRequired) return roleRequired;
      const paymentIntentId = decodePathPart(stripeIntentReconcileMatch[1]);
      const request = parseStripePaymentIntentReconcileRequest(await readJson(ctx.request));
      const paymentIntent = await billing.reconcileStripePaymentIntent(billingCtx, paymentIntentId, request);
      if (!paymentIntent) {
        return json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stripe payment intent ${paymentIntentId} was not found`,
        }, { status: 404 });
      }
      await emitBillingWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
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
          orgId: auth.claims.orgId,
          actorUserId: auth.claims.userId,
          roles: auth.claims.roles,
          invoiceId: paymentIntent.invoiceId,
          paymentIntentId: paymentIntent.id,
          rail: 'CARD',
        });
      }
      return json({ ok: true, paymentIntent }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stablecoins/quotes') {
      const request = parseStablecoinQuoteRequest(await readJson(ctx.request));
      const quote = await billing.createStablecoinQuote(billingCtx, request);
      return json({ ok: true, quote }, { status: 201 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stablecoins/payment-intents') {
      const request = parseStablecoinPaymentIntentRequest(await readJson(ctx.request));
      const paymentIntent = await billing.createStablecoinPaymentIntent(billingCtx, request);
      await emitBillingWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
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
      return json({ ok: true, paymentIntent }, { status: 201 });
    }

    if (ctx.method === 'GET' && stablecoinIntentMatch) {
      const paymentIntentId = decodePathPart(stablecoinIntentMatch[1]);
      const paymentIntent = await billing.getStablecoinPaymentIntent(billingCtx, paymentIntentId);
      if (!paymentIntent) {
        return json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stablecoin payment intent ${paymentIntentId} was not found`,
        }, { status: 404 });
      }
      return json({ ok: true, paymentIntent }, { status: 200 });
    }

    if (ctx.method === 'POST' && stablecoinIntentCancelMatch) {
      const paymentIntentId = decodePathPart(stablecoinIntentCancelMatch[1]);
      const paymentIntent = await billing.cancelStablecoinPaymentIntent(billingCtx, paymentIntentId);
      if (!paymentIntent) {
        return json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stablecoin payment intent ${paymentIntentId} was not found`,
        }, { status: 404 });
      }
      return json({ ok: true, paymentIntent }, { status: 200 });
    }

    if (ctx.method === 'POST' && stablecoinIntentReconcileMatch) {
      const roleRequired = requirePaymentReconcileRole(auth.claims);
      if (roleRequired) return roleRequired;
      const paymentIntentId = decodePathPart(stablecoinIntentReconcileMatch[1]);
      const request = parseStablecoinPaymentIntentReconcileRequest(await readJson(ctx.request));
      const paymentIntent = await billing.reconcileStablecoinPaymentIntent(billingCtx, paymentIntentId, request);
      if (!paymentIntent) {
        return json({
          ok: false,
          code: 'payment_intent_not_found',
          message: `Stablecoin payment intent ${paymentIntentId} was not found`,
        }, { status: 404 });
      }
      await emitBillingWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
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
          orgId: auth.claims.orgId,
          actorUserId: auth.claims.userId,
          roles: auth.claims.roles,
          invoiceId: paymentIntent.invoiceId,
          paymentIntentId: paymentIntent.id,
          rail: 'STABLECOIN',
        });
      }
      return json({ ok: true, paymentIntent }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendBillingError(error);
  }

  return new Response('Not Found', { status: 404 });
}

export function createCloudflareConsoleRouter(opts: ConsoleRouterOptions = {}): FetchHandler {
  const notFound = () => new Response('Not Found', { status: 404 });
  const logger = coerceRouterLogger(opts.logger);
  const billing = opts.billing === undefined ? null : opts.billing;
  const apiKeys = opts.apiKeys === undefined ? null : opts.apiKeys;
  const webhooks = opts.webhooks === undefined ? null : opts.webhooks;

  const handlers: Array<(ctx: CloudflareConsoleContext) => Promise<Response | null>> = [
    handleConsoleHealth,
    handleConsoleReady,
    handleConsoleSession,
    handleConsoleApiKeys,
    handleConsoleWebhooks,
    handleConsoleBilling,
  ];

  return async function handler(request: Request, env?: CfEnv, cfCtx?: CfExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method.toUpperCase();

    if (method === 'OPTIONS') {
      const res = new Response(null, { status: 204 });
      withConsoleCors(res.headers, opts, request);
      return res;
    }

    const ctx: CloudflareConsoleContext = {
      request,
      url,
      pathname,
      method,
      env,
      cfCtx,
      opts,
      logger,
      billing,
      apiKeys,
      webhooks,
    };

    try {
      for (const fn of handlers) {
        const res = await fn(ctx);
        if (res) {
          withConsoleCors(res.headers, opts, request);
          return res;
        }
      }
      return notFound();
    } catch (e: unknown) {
      const res = json({ code: 'internal', message: e instanceof Error ? e.message : String(e) }, { status: 500 });
      withConsoleCors(res.headers, opts, request);
      return res;
    }
  };
}

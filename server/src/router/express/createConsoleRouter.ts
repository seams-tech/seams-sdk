import type { Request, Response, Router as ExpressRouter } from 'express';
import express from 'express';
import { buildCorsOrigins, normalizeCorsOrigin } from '../../core/SessionService';
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
  parseStripeCustomerPortalSessionRequest,
  parseStripeCheckoutSessionRequest,
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
  isConsoleOrgProjectEnvError,
  parseCreateConsoleEnvironmentRequest,
  parseCreateConsoleProjectRequest,
  parseListConsoleProjectsRequest,
  parseListConsoleEnvironmentsRequest,
  parseUpdateConsoleEnvironmentRequest,
  parseUpdateConsoleProjectRequest,
  type ConsoleOrgProjectEnvService,
} from '../../console/orgProjectEnv';
import {
  isConsoleWalletError,
  parseListConsoleWalletsRequest,
  parseSearchConsoleWalletsRequest,
  type ConsoleWalletService,
} from '../../console/wallets';
import {
  isConsolePolicyError,
  parseCreateConsolePolicyRequest,
  parseListConsolePolicyAssignmentsRequest,
  parseSimulateConsolePolicyRequest,
  parseUpsertConsolePolicyAssignmentRequest,
  parseUpdateConsolePolicyRequest,
  type ConsolePolicyService,
} from '../../console/policies';
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
import {
  isConsoleGasSponsorshipError,
  parseCreateConsoleGasSponsorshipRequest,
  parseListConsoleGasSponsorshipRequest,
  parseUpdateConsoleGasSponsorshipRequest,
  type ConsoleGasSponsorshipService,
} from '../../console/gasSponsorship';
import {
  isConsoleSmartWalletError,
  parseCreateConsoleSmartWalletRequest,
  parseListConsoleSmartWalletRequest,
  parseUpdateConsoleSmartWalletRequest,
  type ConsoleSmartWalletService,
} from '../../console/smartWallets';
import {
  isConsoleSettingsError,
  parseGetConsoleSettingsRequest,
  parseUpdateConsoleAppSettingsRequest,
  parseUpdateConsoleSecuritySettingsRequest,
  type ConsoleSettingsService,
} from '../../console/settings';
import {
  isConsoleKeyExportError,
  parseApproveConsoleKeyExportRequest,
  parseCreateConsoleKeyExportRequest,
  parseListConsoleKeyExportsRequest,
  type ConsoleKeyExportService,
} from '../../console/keyExports';
import {
  isConsoleRuntimeSnapshotError,
  parseGetLatestConsoleRuntimeSnapshotRequest,
  parseListConsoleRuntimeSnapshotsRequest,
  parsePublishCurrentConsoleRuntimeSnapshotRequest,
  parsePublishConsoleRuntimeSnapshotRequest,
  type ConsoleRuntimeSnapshotService,
} from '../../console/runtimeSnapshots';
import type { ConsoleAuthClaims, ConsoleAuthResult, ConsoleRouterOptions } from '../console';
import { authenticateConsoleRequest, hasConsoleRole } from '../console';
import {
  buildConsoleExportGovernanceView,
  buildConsoleGasReadinessView,
  buildConsolePolicyCoverageView,
  resolveConsoleInsightsScope,
} from '../consoleInsights';
import { resolveConsoleRuntimeSnapshotPayload } from '../runtimeSnapshotPayload';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';

export interface ExpressConsoleContext {
  opts: ConsoleRouterOptions;
  logger: NormalizedRouterLogger;
  billing: ConsoleBillingService | null;
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  wallets: ConsoleWalletService | null;
  policies: ConsolePolicyService | null;
  apiKeys: ConsoleApiKeyService | null;
  webhooks: ConsoleWebhookService | null;
  gasSponsorship: ConsoleGasSponsorshipService | null;
  smartWallets: ConsoleSmartWalletService | null;
  settings: ConsoleSettingsService | null;
  keyExports: ConsoleKeyExportService | null;
  runtimeSnapshots: ConsoleRuntimeSnapshotService | null;
}

function withConsoleCors(res: Response, opts?: ConsoleRouterOptions, req?: Request): void {
  if (!opts?.corsOrigins) return;

  let allowedOrigin: string | '*' | undefined;
  const normalized = buildCorsOrigins(...(opts.corsOrigins || []));
  if (normalized === '*') {
    allowedOrigin = '*';
    res.set('Access-Control-Allow-Origin', '*');
  } else if (Array.isArray(normalized)) {
    const originRaw = String((req as any)?.headers?.origin || '').trim();
    const originNormalized = normalizeCorsOrigin(originRaw);
    if (originRaw && originNormalized && normalized.includes(originNormalized)) {
      allowedOrigin = originRaw;
      res.set('Access-Control-Allow-Origin', originRaw);
      res.set('Vary', 'Origin');
    }
  }

  res.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.set(
    'Access-Control-Allow-Headers',
    'Content-Type,Authorization,X-Console-Stripe-Webhook-Secret',
  );
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

function sendOrgProjectEnvError(res: Response, error: unknown): void {
  if (isConsoleOrgProjectEnvError(error)) {
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

function sendWalletError(res: Response, error: unknown): void {
  if (isConsoleWalletError(error)) {
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

function sendPolicyError(res: Response, error: unknown): void {
  if (isConsolePolicyError(error)) {
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

function sendGasSponsorshipError(res: Response, error: unknown): void {
  if (isConsoleGasSponsorshipError(error)) {
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

function sendSmartWalletError(res: Response, error: unknown): void {
  if (isConsoleSmartWalletError(error)) {
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

function sendSettingsError(res: Response, error: unknown): void {
  if (isConsoleSettingsError(error)) {
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

function sendKeyExportError(res: Response, error: unknown): void {
  if (isConsoleKeyExportError(error)) {
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

function sendRuntimeSnapshotError(res: Response, error: unknown): void {
  if (isConsoleRuntimeSnapshotError(error)) {
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

async function requireConsoleAuth(
  req: Request,
  res: Response,
  ctx: ExpressConsoleContext,
): Promise<ConsoleAuthClaims | null> {
  const auth = await authenticateConsoleRequest(
    req.headers as Record<string, string | string[] | undefined>,
    ctx.opts.auth,
  );
  if (!auth.ok) {
    sendAuthFailure(res, auth);
    return null;
  }
  return auth.claims;
}

function requireBillingService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleBillingService | null {
  if (ctx.billing) return ctx.billing;
  res.status(501).json({
    ok: false,
    code: 'billing_not_configured',
    message: 'Billing service is not configured on this server',
  });
  return null;
}

function requireApiKeyService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleApiKeyService | null {
  if (ctx.apiKeys) return ctx.apiKeys;
  res.status(501).json({
    ok: false,
    code: 'api_keys_not_configured',
    message: 'API key service is not configured on this server',
  });
  return null;
}

function requireOrgProjectEnvService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleOrgProjectEnvService | null {
  if (ctx.orgProjectEnv) return ctx.orgProjectEnv;
  res.status(501).json({
    ok: false,
    code: 'org_project_env_not_configured',
    message: 'Org/project/environment service is not configured on this server',
  });
  return null;
}

function requireWalletService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleWalletService | null {
  if (ctx.wallets) return ctx.wallets;
  res.status(501).json({
    ok: false,
    code: 'wallets_not_configured',
    message: 'Wallet service is not configured on this server',
  });
  return null;
}

function requirePolicyService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsolePolicyService | null {
  if (ctx.policies) return ctx.policies;
  res.status(501).json({
    ok: false,
    code: 'policies_not_configured',
    message: 'Policy service is not configured on this server',
  });
  return null;
}

function requireWebhookService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleWebhookService | null {
  if (ctx.webhooks) return ctx.webhooks;
  res.status(501).json({
    ok: false,
    code: 'webhooks_not_configured',
    message: 'Webhook service is not configured on this server',
  });
  return null;
}

function requireGasSponsorshipService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleGasSponsorshipService | null {
  if (ctx.gasSponsorship) return ctx.gasSponsorship;
  res.status(501).json({
    ok: false,
    code: 'gas_sponsorship_not_configured',
    message: 'Gas sponsorship service is not configured on this server',
  });
  return null;
}

function requireSmartWalletService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleSmartWalletService | null {
  if (ctx.smartWallets) return ctx.smartWallets;
  res.status(501).json({
    ok: false,
    code: 'smart_wallets_not_configured',
    message: 'Smart wallet service is not configured on this server',
  });
  return null;
}

function requireSettingsService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleSettingsService | null {
  if (ctx.settings) return ctx.settings;
  res.status(501).json({
    ok: false,
    code: 'settings_not_configured',
    message: 'Settings service is not configured on this server',
  });
  return null;
}

function requireKeyExportService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleKeyExportService | null {
  if (ctx.keyExports) return ctx.keyExports;
  res.status(501).json({
    ok: false,
    code: 'key_exports_not_configured',
    message: 'Key export service is not configured on this server',
  });
  return null;
}

function requireRuntimeSnapshotService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleRuntimeSnapshotService | null {
  if (ctx.runtimeSnapshots) return ctx.runtimeSnapshots;
  res.status(501).json({
    ok: false,
    code: 'runtime_snapshots_not_configured',
    message: 'Runtime snapshot service is not configured on this server',
  });
  return null;
}

function requireStripeWebhookSecret(
  req: Request,
  res: Response,
  ctx: ExpressConsoleContext,
): boolean {
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

function toOrgProjectEnvContext(claims: ConsoleAuthClaims): {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
} {
  return {
    orgId: claims.orgId,
    actorUserId: claims.userId,
    roles: claims.roles,
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
  };
}

function toWalletContext(claims: ConsoleAuthClaims): {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
} {
  return {
    orgId: claims.orgId,
    actorUserId: claims.userId,
    roles: claims.roles,
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
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

function requireOrgProjectEnvMutationRole(claims: ConsoleAuthClaims, res: Response): boolean {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'owner')) return true;
  res.status(403).json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin or owner can mutate projects and environments',
  });
  return false;
}

function requirePolicyMutationRole(claims: ConsoleAuthClaims, res: Response): boolean {
  if (
    hasConsoleRole(claims, 'owner') ||
    hasConsoleRole(claims, 'admin') ||
    hasConsoleRole(claims, 'security_admin')
  ) {
    return true;
  }
  res.status(403).json({
    ok: false,
    code: 'forbidden',
    message: 'Only owner, admin, or security_admin can mutate policies',
  });
  return false;
}

function requireConsoleConfigMutationRole(claims: ConsoleAuthClaims, res: Response): boolean {
  if (
    hasConsoleRole(claims, 'owner') ||
    hasConsoleRole(claims, 'admin') ||
    hasConsoleRole(claims, 'security_admin')
  ) {
    return true;
  }
  res.status(403).json({
    ok: false,
    code: 'forbidden',
    message: 'Only owner, admin, or security_admin can mutate console configuration',
  });
  return false;
}

function requireKeyExportApprovalRole(claims: ConsoleAuthClaims, res: Response): boolean {
  if (hasConsoleRole(claims, 'admin')) return true;
  res.status(403).json({
    ok: false,
    code: 'forbidden',
    message: 'Only admin can approve key export requests',
  });
  return false;
}

const BILLING_TERMINAL_SETTLEMENT_STATES = new Set(['SETTLED', 'PARTIALLY_SETTLED', 'OVERPAID']);

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

function registerConsoleOrgProjectEnvRoutes(
  router: ExpressRouter,
  ctx: ExpressConsoleContext,
): void {
  router.get('/console/org', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const org = await orgProjectEnv.getOrganization(toOrgProjectEnvContext(claims));
      res.status(200).json({ ok: true, org });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.get('/console/projects', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const request = parseListConsoleProjectsRequest((req as any).query || {});
      const projects = await orgProjectEnv.listProjects(toOrgProjectEnvContext(claims), request);
      res.status(200).json({ ok: true, projects });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.post('/console/projects', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireOrgProjectEnvMutationRole(claims, res)) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const request = parseCreateConsoleProjectRequest((req as any).body || {});
      const project = await orgProjectEnv.createProject(toOrgProjectEnvContext(claims), request);
      res.status(201).json({ ok: true, project });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.patch('/console/projects/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireOrgProjectEnvMutationRole(claims, res)) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    const projectId = readPathParam(req, 'id');
    if (!projectId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing project id' });
      return;
    }
    try {
      const request = parseUpdateConsoleProjectRequest((req as any).body || {});
      const project = await orgProjectEnv.updateProject(
        toOrgProjectEnvContext(claims),
        projectId,
        request,
      );
      if (!project) {
        res.status(404).json({
          ok: false,
          code: 'project_not_found',
          message: `Project ${projectId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, project });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.post('/console/projects/:id/archive', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireOrgProjectEnvMutationRole(claims, res)) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    const projectId = readPathParam(req, 'id');
    if (!projectId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing project id' });
      return;
    }
    try {
      const project = await orgProjectEnv.archiveProject(toOrgProjectEnvContext(claims), projectId);
      if (!project) {
        res.status(404).json({
          ok: false,
          code: 'project_not_found',
          message: `Project ${projectId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, project });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.get('/console/environments', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const request = parseListConsoleEnvironmentsRequest((req as any).query || {});
      const environments = await orgProjectEnv.listEnvironments(
        toOrgProjectEnvContext(claims),
        request,
      );
      res.status(200).json({ ok: true, environments });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.post('/console/environments', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireOrgProjectEnvMutationRole(claims, res)) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const request = parseCreateConsoleEnvironmentRequest((req as any).body || {});
      const environment = await orgProjectEnv.createEnvironment(
        toOrgProjectEnvContext(claims),
        request,
      );
      res.status(201).json({ ok: true, environment });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.patch('/console/environments/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireOrgProjectEnvMutationRole(claims, res)) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    const environmentId = readPathParam(req, 'id');
    if (!environmentId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing environment id' });
      return;
    }
    try {
      const request = parseUpdateConsoleEnvironmentRequest((req as any).body || {});
      const environment = await orgProjectEnv.updateEnvironment(
        toOrgProjectEnvContext(claims),
        environmentId,
        request,
      );
      if (!environment) {
        res.status(404).json({
          ok: false,
          code: 'environment_not_found',
          message: `Environment ${environmentId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, environment });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });

  router.post('/console/environments/:id/archive', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireOrgProjectEnvMutationRole(claims, res)) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    const environmentId = readPathParam(req, 'id');
    if (!environmentId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing environment id' });
      return;
    }
    try {
      const environment = await orgProjectEnv.archiveEnvironment(
        toOrgProjectEnvContext(claims),
        environmentId,
      );
      if (!environment) {
        res.status(404).json({
          ok: false,
          code: 'environment_not_found',
          message: `Environment ${environmentId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, environment });
    } catch (error: unknown) {
      sendOrgProjectEnvError(res, error);
    }
  });
}

function registerConsoleWalletRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/wallets', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const wallets = requireWalletService(res, ctx);
    if (!wallets) return;
    try {
      const request = parseListConsoleWalletsRequest((req as any).query || {});
      const page = await wallets.listWallets(toWalletContext(claims), request);
      res.status(200).json({
        ok: true,
        wallets: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      });
    } catch (error: unknown) {
      sendWalletError(res, error);
    }
  });

  router.get('/console/wallets/search', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const wallets = requireWalletService(res, ctx);
    if (!wallets) return;
    try {
      const request = parseSearchConsoleWalletsRequest((req as any).query || {});
      const page = await wallets.searchWallets(toWalletContext(claims), request);
      res.status(200).json({
        ok: true,
        wallets: page.items,
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      });
    } catch (error: unknown) {
      sendWalletError(res, error);
    }
  });

  router.get('/console/wallets/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const wallets = requireWalletService(res, ctx);
    if (!wallets) return;
    const walletId = readPathParam(req, 'id');
    if (!walletId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing wallet id' });
      return;
    }
    try {
      const wallet = await wallets.getWallet(toWalletContext(claims), walletId);
      if (!wallet) {
        res.status(404).json({
          ok: false,
          code: 'wallet_not_found',
          message: `Wallet ${walletId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, wallet });
    } catch (error: unknown) {
      sendWalletError(res, error);
    }
  });
}

function registerConsolePolicyRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/policies', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    try {
      const out = await policies.listPolicies(toBillingContext(claims));
      res.status(200).json({ ok: true, policies: out });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.get('/console/policies/assignments', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    try {
      const request = parseListConsolePolicyAssignmentsRequest((req as any).query || {});
      const assignments = await policies.listAssignments(toBillingContext(claims), request);
      res.status(200).json({ ok: true, assignments });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.post('/console/policies', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requirePolicyMutationRole(claims, res)) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    try {
      const request = parseCreateConsolePolicyRequest((req as any).body || {});
      const policy = await policies.createPolicy(toBillingContext(claims), request);
      res.status(201).json({ ok: true, policy });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.put('/console/policies/assignments', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requirePolicyMutationRole(claims, res)) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    try {
      const request = parseUpsertConsolePolicyAssignmentRequest((req as any).body || {});
      const assignment = await policies.upsertAssignment(toBillingContext(claims), request);
      res.status(200).json({ ok: true, assignment });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.delete('/console/policies/assignments/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requirePolicyMutationRole(claims, res)) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    const assignmentId = readPathParam(req, 'id');
    if (!assignmentId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing assignment id' });
      return;
    }
    try {
      const out = await policies.deleteAssignment(toBillingContext(claims), assignmentId);
      if (!out.removed || !out.assignment) {
        res.status(404).json({
          ok: false,
          code: 'assignment_not_found',
          message: `Assignment ${assignmentId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, removed: true, assignment: out.assignment });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.patch('/console/policies/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requirePolicyMutationRole(claims, res)) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    const policyId = readPathParam(req, 'id');
    if (!policyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing policy id' });
      return;
    }
    try {
      const request = parseUpdateConsolePolicyRequest((req as any).body || {});
      const policy = await policies.updatePolicy(toBillingContext(claims), policyId, request);
      if (!policy) {
        res.status(404).json({
          ok: false,
          code: 'policy_not_found',
          message: `Policy ${policyId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, policy });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.post('/console/policies/:id/publish', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requirePolicyMutationRole(claims, res)) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    const policyId = readPathParam(req, 'id');
    if (!policyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing policy id' });
      return;
    }
    try {
      const result = await policies.publishPolicy(toBillingContext(claims), policyId);
      if (!result) {
        res.status(404).json({
          ok: false,
          code: 'policy_not_found',
          message: `Policy ${policyId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, result });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.post('/console/policies/:id/simulate', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    const policyId = readPathParam(req, 'id');
    if (!policyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing policy id' });
      return;
    }
    try {
      const request = parseSimulateConsolePolicyRequest((req as any).body || {});
      const simulation = await policies.simulatePolicy(toBillingContext(claims), policyId, request);
      if (!simulation) {
        res.status(404).json({
          ok: false,
          code: 'policy_not_found',
          message: `Policy ${policyId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, simulation });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });
}

function registerConsoleInsightsRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/policy/coverage', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const wallets = requireWalletService(res, ctx);
    if (!wallets) return;
    const scope = resolveConsoleInsightsScope({
      projectIdRaw: (req as any)?.query?.projectId,
      environmentIdRaw: (req as any)?.query?.environmentId,
      claimsProjectId: claims.projectId,
      claimsEnvironmentId: claims.environmentId,
    });
    try {
      const coverage = await buildConsolePolicyCoverageView({
        wallets,
        walletCtx: toWalletContext(claims),
        scope,
        ...(ctx.policies
          ? {
              resolvePolicyIds: async (walletRows) =>
                await ctx.policies!.resolvePoliciesForWallets(
                  toBillingContext(claims),
                  walletRows.map((wallet) => ({
                    walletId: wallet.id,
                    projectId: wallet.projectId,
                    environmentId: wallet.environmentId,
                    fallbackPolicyId: wallet.policyId,
                  })),
                ),
            }
          : {}),
      });
      res.status(200).json({ ok: true, coverage });
    } catch (error: unknown) {
      sendWalletError(res, error);
    }
  });

  router.get('/console/gas/readiness', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const wallets = requireWalletService(res, ctx);
    if (!wallets) return;
    const scope = resolveConsoleInsightsScope({
      projectIdRaw: (req as any)?.query?.projectId,
      environmentIdRaw: (req as any)?.query?.environmentId,
      claimsProjectId: claims.projectId,
      claimsEnvironmentId: claims.environmentId,
    });
    try {
      const readiness = await buildConsoleGasReadinessView({
        wallets,
        walletCtx: toWalletContext(claims),
        scope,
        recentWindowDays: 7,
      });
      res.status(200).json({ ok: true, readiness });
    } catch (error: unknown) {
      sendWalletError(res, error);
    }
  });

  router.get('/console/export/governance', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    const environmentIdRaw = String((req as any)?.query?.environmentId || '').trim();
    const environmentIdFilter = environmentIdRaw || claims.environmentId || undefined;
    try {
      const governance = await buildConsoleExportGovernanceView({
        apiKeys,
        apiKeyCtx: toBillingContext(claims),
        environmentIdFilter,
      });
      res.status(200).json({ ok: true, governance });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });
}

function registerConsoleGasSponsorshipRoutes(
  router: ExpressRouter,
  ctx: ExpressConsoleContext,
): void {
  router.get('/console/gas-sponsorship', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const gasSponsorship = requireGasSponsorshipService(res, ctx);
    if (!gasSponsorship) return;
    try {
      const request = parseListConsoleGasSponsorshipRequest((req as any).query || {});
      const configs = await gasSponsorship.listConfigs(toBillingContext(claims), request);
      res.status(200).json({ ok: true, configs });
    } catch (error: unknown) {
      sendGasSponsorshipError(res, error);
    }
  });

  router.post('/console/gas-sponsorship', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const gasSponsorship = requireGasSponsorshipService(res, ctx);
    if (!gasSponsorship) return;
    try {
      const request = parseCreateConsoleGasSponsorshipRequest((req as any).body);
      const config = await gasSponsorship.createConfig(toBillingContext(claims), request);
      res.status(201).json({ ok: true, config });
    } catch (error: unknown) {
      sendGasSponsorshipError(res, error);
    }
  });

  router.patch('/console/gas-sponsorship/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const gasSponsorship = requireGasSponsorshipService(res, ctx);
    if (!gasSponsorship) return;
    const configId = readPathParam(req, 'id');
    if (!configId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing gas sponsorship id' });
      return;
    }
    try {
      const request = parseUpdateConsoleGasSponsorshipRequest((req as any).body);
      const config = await gasSponsorship.updateConfig(toBillingContext(claims), configId, request);
      if (!config) {
        res.status(404).json({
          ok: false,
          code: 'gas_sponsorship_not_found',
          message: `Gas sponsorship config ${configId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, config });
    } catch (error: unknown) {
      sendGasSponsorshipError(res, error);
    }
  });
}

function registerConsoleSmartWalletRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/smart-wallets', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const smartWallets = requireSmartWalletService(res, ctx);
    if (!smartWallets) return;
    try {
      const request = parseListConsoleSmartWalletRequest((req as any).query || {});
      const configs = await smartWallets.listConfigs(toBillingContext(claims), request);
      res.status(200).json({ ok: true, configs });
    } catch (error: unknown) {
      sendSmartWalletError(res, error);
    }
  });

  router.post('/console/smart-wallets', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const smartWallets = requireSmartWalletService(res, ctx);
    if (!smartWallets) return;
    try {
      const request = parseCreateConsoleSmartWalletRequest((req as any).body);
      const config = await smartWallets.createConfig(toBillingContext(claims), request);
      res.status(201).json({ ok: true, config });
    } catch (error: unknown) {
      sendSmartWalletError(res, error);
    }
  });

  router.patch('/console/smart-wallets/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const smartWallets = requireSmartWalletService(res, ctx);
    if (!smartWallets) return;
    const configId = readPathParam(req, 'id');
    if (!configId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing smart-wallet config id' });
      return;
    }
    try {
      const request = parseUpdateConsoleSmartWalletRequest((req as any).body);
      const config = await smartWallets.updateConfig(toBillingContext(claims), configId, request);
      if (!config) {
        res.status(404).json({
          ok: false,
          code: 'smart_wallet_config_not_found',
          message: `Smart-wallet config ${configId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, config });
    } catch (error: unknown) {
      sendSmartWalletError(res, error);
    }
  });
}

function registerConsoleSettingsRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/settings/app', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const settings = requireSettingsService(res, ctx);
    if (!settings) return;
    try {
      const request = parseGetConsoleSettingsRequest((req as any).query || {});
      const appSettings = await settings.getAppSettings(toBillingContext(claims), request);
      res.status(200).json({ ok: true, appSettings });
    } catch (error: unknown) {
      sendSettingsError(res, error);
    }
  });

  router.patch('/console/settings/app', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const settings = requireSettingsService(res, ctx);
    if (!settings) return;
    try {
      const request = parseUpdateConsoleAppSettingsRequest((req as any).body);
      const appSettings = await settings.updateAppSettings(toBillingContext(claims), request);
      res.status(200).json({ ok: true, appSettings });
    } catch (error: unknown) {
      sendSettingsError(res, error);
    }
  });

  router.get('/console/settings/security', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const settings = requireSettingsService(res, ctx);
    if (!settings) return;
    try {
      const request = parseGetConsoleSettingsRequest((req as any).query || {});
      const securitySettings = await settings.getSecuritySettings(toBillingContext(claims), request);
      res.status(200).json({ ok: true, securitySettings });
    } catch (error: unknown) {
      sendSettingsError(res, error);
    }
  });

  router.patch('/console/settings/security', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const settings = requireSettingsService(res, ctx);
    if (!settings) return;
    try {
      const request = parseUpdateConsoleSecuritySettingsRequest((req as any).body);
      const securitySettings = await settings.updateSecuritySettings(toBillingContext(claims), request);
      res.status(200).json({ ok: true, securitySettings });
    } catch (error: unknown) {
      sendSettingsError(res, error);
    }
  });
}

function registerConsoleKeyExportRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/key-exports', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const keyExports = requireKeyExportService(res, ctx);
    if (!keyExports) return;
    try {
      const request = parseListConsoleKeyExportsRequest((req as any).query || {});
      const keyExportRows = await keyExports.listKeyExports(toBillingContext(claims), request);
      res.status(200).json({ ok: true, exports: keyExportRows });
    } catch (error: unknown) {
      sendKeyExportError(res, error);
    }
  });

  router.post('/console/key-exports', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const keyExports = requireKeyExportService(res, ctx);
    if (!keyExports) return;
    try {
      const request = parseCreateConsoleKeyExportRequest((req as any).body);
      const keyExport = await keyExports.createKeyExport(toBillingContext(claims), request);
      res.status(201).json({ ok: true, keyExport });
    } catch (error: unknown) {
      sendKeyExportError(res, error);
    }
  });

  router.post('/console/key-exports/:id/approve', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireKeyExportApprovalRole(claims, res)) return;
    const keyExports = requireKeyExportService(res, ctx);
    if (!keyExports) return;
    const exportId = readPathParam(req, 'id');
    if (!exportId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing key export id' });
      return;
    }
    try {
      const request = parseApproveConsoleKeyExportRequest((req as any).body);
      const keyExport = await keyExports.approveKeyExport(toBillingContext(claims), exportId, request);
      if (!keyExport) {
        res.status(404).json({
          ok: false,
          code: 'key_export_not_found',
          message: `Key export request ${exportId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, keyExport });
    } catch (error: unknown) {
      sendKeyExportError(res, error);
    }
  });
}

function registerConsoleRuntimeSnapshotRoutes(
  router: ExpressRouter,
  ctx: ExpressConsoleContext,
): void {
  router.get('/console/runtime-snapshots', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const runtimeSnapshots = requireRuntimeSnapshotService(res, ctx);
    if (!runtimeSnapshots) return;
    try {
      const request = parseListConsoleRuntimeSnapshotsRequest((req as any).query || {});
      const snapshots = await runtimeSnapshots.listSnapshots(toBillingContext(claims), request);
      res.status(200).json({ ok: true, snapshots });
    } catch (error: unknown) {
      sendRuntimeSnapshotError(res, error);
    }
  });

  router.get('/console/runtime-snapshots/latest', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const runtimeSnapshots = requireRuntimeSnapshotService(res, ctx);
    if (!runtimeSnapshots) return;
    try {
      const request = parseGetLatestConsoleRuntimeSnapshotRequest((req as any).query || {});
      const snapshot = await runtimeSnapshots.getLatestSnapshot(toBillingContext(claims), request);
      res.status(200).json({ ok: true, snapshot });
    } catch (error: unknown) {
      sendRuntimeSnapshotError(res, error);
    }
  });

  router.post('/console/runtime-snapshots/publish', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const runtimeSnapshots = requireRuntimeSnapshotService(res, ctx);
    if (!runtimeSnapshots) return;
    try {
      const request = parsePublishConsoleRuntimeSnapshotRequest((req as any).body);
      const snapshot = await runtimeSnapshots.publishSnapshot(toBillingContext(claims), request);
      res.status(201).json({ ok: true, snapshot });
    } catch (error: unknown) {
      sendRuntimeSnapshotError(res, error);
    }
  });

  router.post('/console/runtime-snapshots/publish-current', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims || !requireConsoleConfigMutationRole(claims, res)) return;
    const runtimeSnapshots = requireRuntimeSnapshotService(res, ctx);
    if (!runtimeSnapshots) return;
    try {
      const request = parsePublishCurrentConsoleRuntimeSnapshotRequest((req as any).body);
      const payload = await resolveConsoleRuntimeSnapshotPayload({
        orgId: claims.orgId,
        actorUserId: claims.userId,
        roles: claims.roles,
        environmentId: request.environmentId,
        ...(request.projectId ? { projectId: request.projectId } : {}),
        policies: ctx.policies,
        settings: ctx.settings,
        gasSponsorship: ctx.gasSponsorship,
        smartWallets: ctx.smartWallets,
      });
      const snapshot = await runtimeSnapshots.publishSnapshot(toBillingContext(claims), {
        ...request,
        payload,
      });
      res.status(201).json({ ok: true, snapshot });
    } catch (error: unknown) {
      sendRuntimeSnapshotError(res, error);
    }
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
      res
        .status(400)
        .json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
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
      res
        .status(400)
        .json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
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
      res
        .status(400)
        .json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
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
      res
        .status(400)
        .json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
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
      res
        .status(400)
        .json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
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
      res
        .status(400)
        .json({ ok: false, code: 'invalid_path', message: 'Missing webhook endpoint id' });
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

  router.get(
    '/console/billing/usage/monthly-active-wallets',
    async (req: Request, res: Response) => {
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
    },
  );

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
        res.status(404).json({
          ok: false,
          code: 'invoice_not_found',
          message: `Invoice ${invoiceId} was not found`,
        });
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
        res.status(404).json({
          ok: false,
          code: 'invoice_not_found',
          message: `Invoice ${invoiceId} was not found`,
        });
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
      res
        .status(400)
        .json({ ok: false, code: 'invalid_path', message: 'Missing payment method id' });
      return;
    }
    try {
      const out = await billing.removeCardPaymentMethod(toBillingContext(claims), paymentMethodId);
      if (!out.removed) {
        res.status(404).json({
          ok: false,
          code: 'payment_method_not_found',
          message: `Payment method ${paymentMethodId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, removed: true });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post(
    '/console/billing/payment-methods/:id/default',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims || !requireAdminRoleForCardActions(claims, res)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      const paymentMethodId = readPathParam(req, 'id');
      if (!paymentMethodId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_path', message: 'Missing payment method id' });
        return;
      }
      try {
        const paymentMethod = await billing.setDefaultCardPaymentMethod(
          toBillingContext(claims),
          paymentMethodId,
        );
        if (!paymentMethod) {
          res.status(404).json({
            ok: false,
            code: 'payment_method_not_found',
            message: `Payment method ${paymentMethodId} was not found`,
          });
          return;
        }
        res.status(200).json({ ok: true, paymentMethod });
      } catch (error: unknown) {
        sendBillingError(res, error);
      }
    },
  );

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

  router.post('/console/billing/stripe/checkout-session', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseStripeCheckoutSessionRequest((req as any).body);
      const checkoutSession = await billing.createStripeCheckoutSession(
        toBillingContext(claims),
        request,
      );
      res.status(201).json({ ok: true, checkoutSession });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post(
    '/console/billing/stripe/customer-portal-session',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      try {
        const request = parseStripeCustomerPortalSessionRequest((req as any).body);
        const portalSession = await billing.createStripeCustomerPortalSession(
          toBillingContext(claims),
          request,
        );
        res.status(201).json({ ok: true, portalSession });
      } catch (error: unknown) {
        sendBillingError(res, error);
      }
    },
  );

  router.get('/console/billing/subscription', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const subscription = await billing.getSubscription(toBillingContext(claims));
      res.status(200).json({ ok: true, subscription });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/subscription/cancel', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const subscription = await billing.cancelSubscription(toBillingContext(claims));
      res.status(200).json({ ok: true, subscription });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post('/console/billing/subscription/resume', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const subscription = await billing.resumeSubscription(toBillingContext(claims));
      res.status(200).json({ ok: true, subscription });
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
      const paymentIntent = await billing.createStripePaymentIntent(
        toBillingContext(claims),
        request,
      );
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

  router.post(
    '/console/billing/stripe/payment-intents/:id/reconcile',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims || !requirePaymentReconcileRole(claims, res)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      const paymentIntentId = readPathParam(req, 'id');
      if (!paymentIntentId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
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
    },
  );

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

  router.post(
    '/console/billing/stablecoins/payment-intents',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      try {
        const request = parseStablecoinPaymentIntentRequest((req as any).body);
        const paymentIntent = await billing.createStablecoinPaymentIntent(
          toBillingContext(claims),
          request,
        );
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
    },
  );

  router.get(
    '/console/billing/stablecoins/payment-intents/:id',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      const paymentIntentId = readPathParam(req, 'id');
      if (!paymentIntentId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
        return;
      }
      try {
        const paymentIntent = await billing.getStablecoinPaymentIntent(
          toBillingContext(claims),
          paymentIntentId,
        );
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
    },
  );

  router.post(
    '/console/billing/stablecoins/payment-intents/:id/cancel',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      const paymentIntentId = readPathParam(req, 'id');
      if (!paymentIntentId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
        return;
      }
      try {
        const paymentIntent = await billing.cancelStablecoinPaymentIntent(
          toBillingContext(claims),
          paymentIntentId,
        );
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
    },
  );

  router.post(
    '/console/billing/stablecoins/payment-intents/:id/reconcile',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims || !requirePaymentReconcileRole(claims, res)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      const paymentIntentId = readPathParam(req, 'id');
      if (!paymentIntentId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_path', message: 'Missing payment intent id' });
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
    },
  );
}

export function createConsoleRouter(opts: ConsoleRouterOptions = {}): ExpressRouter {
  const router = express.Router();
  const logger = coerceRouterLogger(opts.logger);
  const billing = opts.billing === undefined ? null : opts.billing;
  const orgProjectEnv = opts.orgProjectEnv === undefined ? null : opts.orgProjectEnv;
  const wallets = opts.wallets === undefined ? null : opts.wallets;
  const policies = opts.policies === undefined ? null : opts.policies;
  const apiKeys = opts.apiKeys === undefined ? null : opts.apiKeys;
  const webhooks = opts.webhooks === undefined ? null : opts.webhooks;
  const gasSponsorship = opts.gasSponsorship === undefined ? null : opts.gasSponsorship;
  const smartWallets = opts.smartWallets === undefined ? null : opts.smartWallets;
  const settings = opts.settings === undefined ? null : opts.settings;
  const keyExports = opts.keyExports === undefined ? null : opts.keyExports;
  const runtimeSnapshots = opts.runtimeSnapshots === undefined ? null : opts.runtimeSnapshots;

  installConsoleCors(router, opts);

  const ctx: ExpressConsoleContext = {
    opts,
    logger,
    billing,
    orgProjectEnv,
    wallets,
    policies,
    apiKeys,
    webhooks,
    gasSponsorship,
    smartWallets,
    settings,
    keyExports,
    runtimeSnapshots,
  };

  registerConsoleHealthRoutes(router, ctx);
  registerConsoleSessionRoute(router, ctx);
  registerConsoleOrgProjectEnvRoutes(router, ctx);
  registerConsoleWalletRoutes(router, ctx);
  registerConsolePolicyRoutes(router, ctx);
  registerConsoleInsightsRoutes(router, ctx);
  registerConsoleGasSponsorshipRoutes(router, ctx);
  registerConsoleSmartWalletRoutes(router, ctx);
  registerConsoleSettingsRoutes(router, ctx);
  registerConsoleKeyExportRoutes(router, ctx);
  registerConsoleRuntimeSnapshotRoutes(router, ctx);
  registerConsoleApiKeyRoutes(router, ctx);
  registerConsoleWebhookRoutes(router, ctx);
  registerConsoleBillingRoutes(router, ctx);

  return router;
}

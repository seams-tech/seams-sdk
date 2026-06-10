import type { Request, Response, Router as ExpressRouter } from 'express';
import express from 'express';
import { buildCorsOrigins, normalizeCorsOrigin } from '../../core/SessionService';
import {
  buildConsoleBillingInvoicePdf,
  buildConsoleBillingInvoicePdfFilename,
  CONSOLE_BILLING_INVOICE_PDF_EXPORT_POLICY,
  ConsoleBillingError,
  LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE,
  ensureBillingReadyForLiveEnvironment,
  getBillingLiveEnvironmentReadiness,
  isConsoleBillingError,
  parseBillingAccountActivityRequest,
  parseBillingInvoiceListRequest,
  parseBillingManualAdjustmentRequest,
  parseStripeCheckoutSessionReconcileRequest,
  parseBillingUsageEventRequest,
  parseGenerateMonthlyInvoiceRequest,
  parseStripeWebhookEventRequest,
  parseStripeCheckoutSessionRequest,
  type ConsoleBillingService,
} from '../../console/billing';
import type { ConsoleBillingPrepaidReservationService } from '../../console/billingPrepaidReservations';
import {
  isConsoleSponsoredCallError,
  listConsoleSponsoredCallReconciliationPage,
  parseListConsoleSponsoredCallRecordsRequest,
  type ConsoleSponsoredCallService,
} from '../../console/sponsoredCalls';
import {
  isConsoleApiKeyError,
  parseCreateConsoleApiKeyRequest,
  parseRevokeConsoleApiKeyRequest,
  parseRotateConsoleApiKeyRequest,
  parseUpdateConsoleApiKeyRequest,
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
  parseListConsolePoliciesRequest,
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
import {
  isConsoleTeamRbacError,
  parseInviteConsoleTeamMemberRequest,
  parseListConsoleTeamMembersRequest,
  parseUpdateConsoleTeamMemberRolesRequest,
  type ConsoleTeamRbacService,
} from '../../console/teamRbac';
import {
  type CreateConsoleApprovalRequest,
  type ConsoleApprovalOperationType,
  isConsoleApprovalsError,
  parseApproveConsoleApprovalRequest,
  parseCreateConsoleApprovalRequest,
  parseListConsoleApprovalsRequest,
  parseRejectConsoleApprovalRequest,
  type ConsoleApprovalService,
} from '../../console/approvals';
import {
  isConsoleAuditError,
  parseListConsoleAuditEventsRequest,
  parseListConsoleAuditEvidenceRequest,
  type ConsoleAuditService,
} from '../../console/audit';
import {
  isConsoleAuditExportsError,
  parseCreateConsoleAuditExportRequest,
  parseListConsoleAuditExportsRequest,
  type ConsoleAuditExportsService,
} from '../../console/auditExports';
import {
  isConsoleEnterpriseIsolationError,
  parseGetConsoleEnterpriseIsolationRequest,
  parseTriggerConsoleEnterpriseIsolationRequest,
  type ConsoleEnterpriseIsolationService,
} from '../../console/enterpriseIsolation';
import {
  isConsoleOnboardingError,
  parseCreateConsoleOnboardingOrganizationRequest,
  parseCreateConsoleOnboardingProjectRequest,
  parseGetConsoleOnboardingStateRequest,
  parseGetConsoleOnboardingTelemetryRequest,
  type ConsoleOnboardingService,
} from '../../console/onboarding';
import {
  isConsoleAccountError,
  parseCreateConsoleAccountOrganizationRequest,
  parsePatchConsoleAccountProfileRequest,
  parseTransferConsoleAccountOrganizationOwnerRequest,
  parseUpdateConsoleAccountOrganizationRequest,
  type ConsoleAccountService,
} from '../../console/account';
import {
  isConsoleObservabilityError,
  type ConsoleObservabilityIngestionService,
  type ConsoleObservabilityService,
} from '../../console/observability';
import type { ConsoleAuthClaims, ConsoleAuthResult, ConsoleRouterOptions } from '../console';
import { authenticateConsoleRequest, hasConsoleRole } from '../console';
import {
  emitConsoleApprovalFailureObservabilityEvent,
  emitConsoleBillingFailureObservabilityEvent,
  emitConsoleBillingStripeWebhookFailureObservabilityEvent,
  observeConsoleRequestMetric,
  readConsoleStripeWebhookFailureMetadata,
} from '../consoleObservabilityHooks';
import {
  buildConsoleContextSwitchSessionClaims,
  parseConsoleSessionForContextSwitch,
} from '../consoleSessionContext';
import {
  buildConsoleExportGovernanceView,
  buildConsoleGasReadinessView,
  buildConsolePolicyCoverageView,
  resolveConsoleInsightsScope,
} from '../consoleInsights';
import {
  type ConsolePolicyPresentation,
  listConsolePolicyPresentationLookup,
  projectConsolePolicyPresentation,
  resolveConsolePolicyPresentation,
} from '../policyPresentation';
import {
  buildConsoleBillingInvoiceGeneratedAuditEvent,
  buildConsoleBillingCreditPurchaseSettledAuditEvent,
  buildConsolePolicyAssignmentAuditEvent,
  buildConsolePolicyAuditEvent,
  buildConsoleWebhookEndpointAuditEvent,
  buildConsoleWebhookReplayAuditEvent,
} from '../consoleAuditMetadata';
import {
  parsePlatformBillingLookupRequest,
  parsePlatformBillingSearchRequest,
  parsePlatformBillingManualAdjustmentRequest,
  resolvePlatformBillingLookup,
  searchPlatformBillingOrganizations,
} from '../platformBilling';
import { resolveConsoleRuntimeSnapshotPayload } from '../runtimeSnapshotPayload';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';
import { buildConsoleOpsCockpitSummary } from '../opsCockpitSummary';
import type { SessionAdapter } from '../relay';
import {
  emitSponsorshipBalanceTransitionEvents,
  readSponsorshipBillingBalanceSnapshot,
} from '../sponsorshipBillingEvents';
import { attachConsoleRouteSurface, resolveConsoleRouteSurface } from '../consoleRouteSurface';
import { authorizeConsoleRouteRequest } from '../consoleRoutePolicy';
import type { RouteDefinition } from '../routeDefinitions';
import { registerConsoleObservabilityRoutes } from './consoleObservabilityRoutes';

export interface ExpressConsoleContext {
  opts: ConsoleRouterOptions;
  logger: NormalizedRouterLogger;
  routeDefinitions: readonly RouteDefinition[];
  billing: ConsoleBillingService | null;
  prepaidReservations: ConsoleBillingPrepaidReservationService | null;
  sponsoredCalls: ConsoleSponsoredCallService | null;
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  wallets: ConsoleWalletService | null;
  policies: ConsolePolicyService | null;
  apiKeys: ConsoleApiKeyService | null;
  webhooks: ConsoleWebhookService | null;
  keyExports: ConsoleKeyExportService | null;
  runtimeSnapshots: ConsoleRuntimeSnapshotService | null;
  teamRbac: ConsoleTeamRbacService | null;
  approvals: ConsoleApprovalService | null;
  audit: ConsoleAuditService | null;
  auditExports: ConsoleAuditExportsService | null;
  enterpriseIsolation: ConsoleEnterpriseIsolationService | null;
  onboarding: ConsoleOnboardingService | null;
  account: ConsoleAccountService | null;
  observability: ConsoleObservabilityService | null;
  observabilityIngestion: ConsoleObservabilityIngestionService | null;
}

const CONSOLE_CORS_ALLOW_HEADERS =
  'Content-Type,Authorization,X-Console-Org-Id,X-Console-User-Id,X-Console-Roles,X-Console-Project-Id,X-Console-Environment-Id,X-Console-Stripe-Webhook-Secret';
const CONSOLE_AUTH_CLAIMS = Symbol('console-auth-claims');

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
  res.set('Access-Control-Allow-Headers', CONSOLE_CORS_ALLOW_HEADERS);
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

function setRequestAuthClaims(req: Request, claims: ConsoleAuthClaims): void {
  (req as Record<PropertyKey, unknown>)[CONSOLE_AUTH_CLAIMS] = claims;
}

function getRequestAuthClaims(req: Request): ConsoleAuthClaims | null {
  const raw = (req as Record<PropertyKey, unknown>)[CONSOLE_AUTH_CLAIMS];
  if (!raw || typeof raw !== 'object') return null;
  return raw as ConsoleAuthClaims;
}

function readOptionalExpressHeader(req: Request, header: string): string | undefined {
  const raw = ((req as any)?.headers || {})[header.toLowerCase()] as string | string[] | undefined;
  const value = Array.isArray(raw) ? String(raw[0] || '').trim() : String(raw || '').trim();
  return value || undefined;
}

function installConsoleObservabilityTiming(
  router: ExpressRouter,
  ctx: ExpressConsoleContext,
): void {
  if (!ctx.observabilityIngestion?.observeRequestMetric) return;

  router.use((req: Request, res: Response, next: any) => {
    const startedAtMs = Date.now();
    (res as { on?: (event: 'finish', listener: () => void) => unknown }).on?.('finish', () => {
      const claims = getRequestAuthClaims(req);
      if (!claims?.orgId) return;

      const route =
        String((req as any)?.route?.path || '').trim() ||
        String((req as any)?.path || '').trim() ||
        String((req as any)?.originalUrl || '')
          .split('?')[0]
          .trim() ||
        '/';
      const method = String((req as any)?.method || '').toUpperCase();
      const latencyMs = Math.max(0, Date.now() - startedAtMs);
      const statusCode = Math.max(0, Number((res as any).statusCode || 0));
      void observeConsoleRequestMetric(ctx, {
        claims,
        route,
        method,
        statusCode,
        latencyMs,
      });
    });
    next();
  });
}

async function emitBillingFailureObservabilityEvent(
  ctx: ExpressConsoleContext,
  req: Request,
  claims: ConsoleAuthClaims,
  input: {
    operation: 'INVOICE_FINALIZATION' | 'PAYMENT_RECONCILE';
    invoiceId?: string;
    providerRef?: string;
    error: unknown;
  },
): Promise<void> {
  await emitConsoleBillingFailureObservabilityEvent(ctx, {
    claims,
    operation: input.operation,
    ...(input.invoiceId ? { invoiceId: input.invoiceId } : {}),
    ...(input.providerRef ? { providerRef: input.providerRef } : {}),
    failureCode: isConsoleBillingError(input.error) ? input.error.code : 'internal',
    failureMessage: input.error instanceof Error ? input.error.message : String(input.error),
    readHeader: (header) => readOptionalExpressHeader(req, header),
  });
}

async function emitStripeWebhookFailureObservabilityEvent(
  ctx: ExpressConsoleContext,
  req: Request,
  input: {
    rawBody: unknown;
    eventType:
      | 'billing.stripe_webhook.invalid_signature'
      | 'billing.stripe_webhook.processing.failed';
    failureCode: string;
    failureMessage: string;
  },
): Promise<void> {
  const metadata = readConsoleStripeWebhookFailureMetadata(input.rawBody);
  if (!metadata.orgId) return;
  await emitConsoleBillingStripeWebhookFailureObservabilityEvent(ctx, {
    orgId: metadata.orgId,
    actorUserId: 'system-stripe-webhook',
    eventType: input.eventType,
    ...(metadata.stripeEventId ? { stripeEventId: metadata.stripeEventId } : {}),
    ...(metadata.stripeEventType ? { stripeEventType: metadata.stripeEventType } : {}),
    ...(metadata.checkoutSessionId ? { checkoutSessionId: metadata.checkoutSessionId } : {}),
    ...(metadata.providerRef ? { providerRef: metadata.providerRef } : {}),
    ...(metadata.providerCustomerRef ? { providerCustomerRef: metadata.providerCustomerRef } : {}),
    failureCode: input.failureCode,
    failureMessage: input.failureMessage,
    readHeader: (header) => readOptionalExpressHeader(req, header),
  });
}

async function emitApprovalFailureObservabilityEvent(
  ctx: ExpressConsoleContext,
  req: Request,
  claims: ConsoleAuthClaims,
  input: {
    approvalId?: string;
    operationType: string;
    resourceType?: string;
    resourceId?: string;
    error: unknown;
  },
): Promise<void> {
  await emitConsoleApprovalFailureObservabilityEvent(ctx, {
    claims,
    ...(input.approvalId ? { approvalId: input.approvalId } : {}),
    operationType: input.operationType,
    ...(input.resourceType ? { resourceType: input.resourceType } : {}),
    ...(input.resourceId ? { resourceId: input.resourceId } : {}),
    failureCode: isConsolePolicyError(input.error) ? input.error.code : 'internal',
    failureMessage: input.error instanceof Error ? input.error.message : String(input.error),
    readHeader: (header) => readOptionalExpressHeader(req, header),
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

function sendSponsoredCallError(res: Response, error: unknown): void {
  if (isConsoleSponsoredCallError(error)) {
    res.status(error.status).json({
      ok: false,
      code: error.code,
      message: error.message,
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

function sendTeamRbacError(res: Response, error: unknown): void {
  if (isConsoleTeamRbacError(error)) {
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

function sendApprovalError(res: Response, error: unknown): void {
  if (isConsoleApprovalsError(error)) {
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

function sendAuditError(res: Response, error: unknown): void {
  if (isConsoleAuditError(error)) {
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

function sendAuditExportsError(res: Response, error: unknown): void {
  if (isConsoleAuditExportsError(error)) {
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

function sendEnterpriseIsolationError(res: Response, error: unknown): void {
  if (isConsoleEnterpriseIsolationError(error)) {
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

function sendOnboardingError(res: Response, error: unknown): void {
  if (isConsoleOnboardingError(error)) {
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

function sendObservabilityError(res: Response, error: unknown): void {
  if (isConsoleObservabilityError(error)) {
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

function sendAccountError(res: Response, error: unknown): void {
  if (isConsoleAccountError(error)) {
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
  setRequestAuthClaims(req, auth.claims);
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

async function buildConsoleBillingOverviewResponse(
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  billing: ConsoleBillingService,
): Promise<Record<string, unknown>> {
  const billingCtx = toBillingContext(claims);
  const overview = await billing.getOverview(billingCtx);
  const prepaidSummary = ctx.prepaidReservations
    ? await ctx.prepaidReservations.getSummary(billingCtx)
    : null;
  const sponsoredSummary = ctx.sponsoredCalls
    ? await ctx.sponsoredCalls.getOverviewSummary(billingCtx)
    : null;
  return {
    ...overview,
    reservedSponsorshipMinor: prepaidSummary?.reservedMinor || 0,
    activeSponsorshipReservationCount: prepaidSummary?.activeReservationCount || 0,
    trailing30DaySponsoredSpendMinor:
      sponsoredSummary?.trailing30Days.chargedSettledSpendMinor || 0,
    trailing30DaySponsoredExecutionCount:
      sponsoredSummary?.trailing30Days.chargedExecutionCount || 0,
    trailing90DaySponsoredSpendMinor:
      sponsoredSummary?.trailing90Days.chargedSettledSpendMinor || 0,
    trailing90DaySponsoredExecutionCount:
      sponsoredSummary?.trailing90Days.chargedExecutionCount || 0,
  };
}

function requireSponsoredCallService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleSponsoredCallService | null {
  if (ctx.sponsoredCalls) return ctx.sponsoredCalls;
  res.status(501).json({
    ok: false,
    code: 'sponsored_calls_not_configured',
    message: 'Sponsored call service is not configured on this server',
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

function requireTeamRbacService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleTeamRbacService | null {
  if (ctx.teamRbac) return ctx.teamRbac;
  res.status(501).json({
    ok: false,
    code: 'team_rbac_not_configured',
    message: 'Team RBAC service is not configured on this server',
  });
  return null;
}

function requireApprovalService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleApprovalService | null {
  if (ctx.approvals) return ctx.approvals;
  res.status(501).json({
    ok: false,
    code: 'approvals_not_configured',
    message: 'Approvals service is not configured on this server',
  });
  return null;
}

function requireAuditService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleAuditService | null {
  if (ctx.audit) return ctx.audit;
  res.status(501).json({
    ok: false,
    code: 'audit_not_configured',
    message: 'Audit service is not configured on this server',
  });
  return null;
}

function requireAuditExportsService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleAuditExportsService | null {
  if (ctx.auditExports) return ctx.auditExports;
  res.status(501).json({
    ok: false,
    code: 'audit_exports_not_configured',
    message: 'Audit exports service is not configured on this server',
  });
  return null;
}

function requireEnterpriseIsolationService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleEnterpriseIsolationService | null {
  if (ctx.enterpriseIsolation) return ctx.enterpriseIsolation;
  res.status(501).json({
    ok: false,
    code: 'enterprise_isolation_not_configured',
    message: 'Enterprise isolation service is not configured on this server',
  });
  return null;
}

function requireOnboardingService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleOnboardingService | null {
  if (ctx.onboarding) return ctx.onboarding;
  res.status(501).json({
    ok: false,
    code: 'onboarding_not_configured',
    message: 'Onboarding service is not configured on this server',
  });
  return null;
}

function requireAccountService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleAccountService | null {
  if (ctx.account) return ctx.account;
  res.status(501).json({
    ok: false,
    code: 'account_not_configured',
    message: 'Account service is not configured on this server',
  });
  return null;
}

function requireSessionAdapter(res: Response, ctx: ExpressConsoleContext): SessionAdapter | null {
  if (ctx.opts.session) return ctx.opts.session;
  res.status(501).json({
    ok: false,
    code: 'session_not_configured',
    message: 'Session adapter is not configured on this server',
  });
  return null;
}

function requireObservabilityService(
  res: Response,
  ctx: ExpressConsoleContext,
): ConsoleObservabilityService | null {
  if (ctx.observability) return ctx.observability;
  res.status(501).json({
    ok: false,
    code: 'observability_not_configured',
    message: 'Observability service is not configured on this server',
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

function toTeamRbacContext(claims: ConsoleAuthClaims): {
  orgId: string;
  actorUserId: string;
  roles: string[];
  actorEmail?: string;
  actorDisplayName?: string;
  projectId?: string;
} {
  return {
    orgId: claims.orgId,
    actorUserId: claims.userId,
    roles: claims.roles,
    ...(typeof claims.email === 'string' && claims.email.trim()
      ? { actorEmail: claims.email.trim().toLowerCase() }
      : {}),
    ...(typeof claims.name === 'string' && claims.name.trim()
      ? { actorDisplayName: claims.name.trim() }
      : {}),
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
  };
}

function toApprovalContext(claims: ConsoleAuthClaims): {
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

function toAuditContext(claims: ConsoleAuthClaims): {
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

async function projectApprovalResponse(
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  row: {
    resourceType: string | null;
    resourceId: string | null;
    metadata: Record<string, unknown>;
  },
): Promise<typeof row & ConsolePolicyPresentation> {
  const policyPresentationLookup = await listConsolePolicyPresentationLookup(
    ctx.policies,
    toBillingContext(claims),
  );
  return {
    ...row,
    ...projectConsolePolicyPresentation({
      resourceType: row.resourceType,
      resourceId: row.resourceId,
      metadata: row.metadata,
      policyPresentationLookup,
    }),
  };
}

async function projectApprovalResponses<T extends {
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown>;
}>(
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  rows: readonly T[],
): Promise<Array<T & ConsolePolicyPresentation>> {
  const policyPresentationLookup = await listConsolePolicyPresentationLookup(
    ctx.policies,
    toBillingContext(claims),
  );
  return rows.map((row) => ({
    ...row,
    ...projectConsolePolicyPresentation({
      resourceType: row.resourceType,
      resourceId: row.resourceId,
      metadata: row.metadata,
      policyPresentationLookup,
    }),
  }));
}

async function enrichPolicyApprovalCreateRequest(
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  request: CreateConsoleApprovalRequest,
): Promise<CreateConsoleApprovalRequest> {
  if (request.operationType !== 'POLICY_PUBLISH') return request;
  const resourceType = String(request.resourceType || '').trim().toUpperCase();
  const resourceId = String(request.resourceId || '').trim();
  if (resourceType !== 'POLICY' || !resourceId) return request;
  const policy = await resolveConsolePolicyPresentation(ctx.policies, toBillingContext(claims), resourceId);
  const metadata =
    request.metadata && typeof request.metadata === 'object' && !Array.isArray(request.metadata)
      ? { ...request.metadata }
      : {};
  metadata.policyId = policy.policyId || resourceId;
  if (policy.policyName) metadata.policyName = policy.policyName;
  if (policy.policyKind) metadata.policyKind = policy.policyKind;
  return {
    ...request,
    metadata,
  };
}

async function projectAuditEventResponses<T extends {
  metadata: Record<string, unknown>;
}>(
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  rows: readonly T[],
): Promise<Array<T & ConsolePolicyPresentation>> {
  const policyPresentationLookup = await listConsolePolicyPresentationLookup(
    ctx.policies,
    toBillingContext(claims),
  );
  return rows.map((row) => ({
    ...row,
    ...projectConsolePolicyPresentation({
      metadata: row.metadata,
      policyPresentationLookup,
    }),
  }));
}

async function resolveWalletPolicyPresentationByWalletId(
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  walletRows: ReadonlyArray<{
    id: string;
    projectId?: string | null;
    environmentId?: string | null;
    policyId?: string | null;
  }>,
): Promise<Record<string, ConsolePolicyPresentation>> {
  if (!ctx.policies || walletRows.length === 0) return {};
  const [resolvedPolicyIds, policyPresentationLookup] = await Promise.all([
    ctx.policies.resolvePoliciesForWallets(
      toBillingContext(claims),
      walletRows.map((wallet) => ({
        walletId: wallet.id,
        projectId: wallet.projectId || undefined,
        environmentId: wallet.environmentId || undefined,
        fallbackPolicyId: wallet.policyId || null,
      })),
    ),
    listConsolePolicyPresentationLookup(ctx.policies, toBillingContext(claims)),
  ]);
  const out: Record<string, ConsolePolicyPresentation> = {};
  for (const wallet of walletRows) {
    const policyIdRaw =
      resolvedPolicyIds[wallet.id] === undefined ? wallet.policyId || null : resolvedPolicyIds[wallet.id];
    const policyId = String(policyIdRaw || '').trim() || null;
    const policy = policyId ? policyPresentationLookup[policyId] : undefined;
    out[wallet.id] = {
      policyId,
      policyName: policy?.policyName || null,
      policyKind: policy?.policyKind || null,
    };
  }
  return out;
}

function toOnboardingContext(claims: ConsoleAuthClaims): {
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

function toAccountContext(claims: ConsoleAuthClaims): {
  userId: string;
  orgId: string;
  roles: string[];
  email?: string;
  name?: string;
  provider?: string;
  projectId?: string;
  environmentId?: string;
} {
  return {
    userId: claims.userId,
    orgId: claims.orgId,
    roles: claims.roles,
    ...(typeof claims.email === 'string' && claims.email.trim()
      ? { email: claims.email.trim().toLowerCase() }
      : {}),
    ...(typeof claims.name === 'string' && claims.name.trim() ? { name: claims.name.trim() } : {}),
    ...(typeof claims.provider === 'string' && claims.provider.trim()
      ? { provider: claims.provider.trim() }
      : {}),
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
  };
}

function readApprovalIdFromBody(body: unknown): string {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return '';
  return String((body as Record<string, unknown>).approvalId || '').trim();
}

async function requireApprovedOperationApproval(
  res: Response,
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  input: {
    operationType: ConsoleApprovalOperationType;
    approvalIdRaw: unknown;
    projectId?: string;
    environmentId?: string;
    resourceType?: string;
    resourceId?: string;
  },
): Promise<boolean> {
  if (!ctx.approvals) return true;

  const approvalId = String(input.approvalIdRaw || '').trim();
  if (!approvalId) {
    res.status(400).json({
      ok: false,
      code: 'approval_required',
      message: `Field approvalId is required for ${input.operationType} when approvals service is configured`,
    });
    return false;
  }

  let approval: Awaited<ReturnType<ConsoleApprovalService['getApprovalRequest']>> = null;
  try {
    approval = await ctx.approvals.getApprovalRequest(toApprovalContext(claims), approvalId);
  } catch (error: unknown) {
    sendApprovalError(res, error);
    return false;
  }

  if (!approval) {
    res.status(404).json({
      ok: false,
      code: 'approval_not_found',
      message: `Approval request ${approvalId} was not found`,
    });
    return false;
  }

  if (approval.operationType !== input.operationType) {
    res.status(409).json({
      ok: false,
      code: 'approval_operation_mismatch',
      message: `Approval request ${approvalId} is ${approval.operationType}; expected ${input.operationType}`,
    });
    return false;
  }

  if (approval.status !== 'APPROVED') {
    res.status(409).json({
      ok: false,
      code: 'approval_not_approved',
      message: `Approval request ${approvalId} is ${approval.status}; expected APPROVED`,
    });
    return false;
  }

  const projectId = String(input.projectId || '').trim();
  if (projectId && approval.projectId && approval.projectId !== projectId) {
    res.status(409).json({
      ok: false,
      code: 'approval_scope_mismatch',
      message: `Approval request ${approvalId} project scope does not match request`,
    });
    return false;
  }

  const environmentId = String(input.environmentId || '').trim();
  if (environmentId && approval.environmentId && approval.environmentId !== environmentId) {
    res.status(409).json({
      ok: false,
      code: 'approval_scope_mismatch',
      message: `Approval request ${approvalId} environment scope does not match request`,
    });
    return false;
  }

  const resourceType = String(input.resourceType || '').trim();
  if (resourceType && approval.resourceType && approval.resourceType !== resourceType) {
    res.status(409).json({
      ok: false,
      code: 'approval_resource_mismatch',
      message: `Approval request ${approvalId} resource type does not match request`,
    });
    return false;
  }

  const resourceId = String(input.resourceId || '').trim();
  if (resourceId && approval.resourceId && approval.resourceId !== resourceId) {
    res.status(409).json({
      ok: false,
      code: 'approval_resource_mismatch',
      message: `Approval request ${approvalId} resource id does not match request`,
    });
    return false;
  }

  return true;
}

function readPathParam(req: Request, key: string): string {
  return String((req as any)?.params?.[key] || '').trim();
}

function readRoutePattern(req: Request): string {
  const routePath = (req as any)?.route?.path;
  if (typeof routePath === 'string' && routePath.trim()) return routePath;
  return String((req as any)?.path || '').trim();
}

function requireConsoleRoutePolicy(
  req: Request,
  res: Response,
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
): RouteDefinition | null {
  const authz = authorizeConsoleRouteRequest({
    claims,
    definitions: ctx.routeDefinitions,
    method: String((req as any)?.method || '').trim().toUpperCase(),
    pathname: readRoutePattern(req),
  });
  if (authz.ok) return authz.route;
  res.status(authz.status).json(authz.body);
  return null;
}

async function requireActiveApiKeyEnvironmentForCreate(
  res: Response,
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  environmentId: string,
): Promise<boolean> {
  const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
  if (!orgProjectEnv) return false;
  try {
    const environments = await orgProjectEnv.listEnvironments(toOrgProjectEnvContext(claims));
    const environment = environments.find((entry) => entry.id === environmentId);
    if (!environment) {
      res.status(400).json({
        ok: false,
        code: 'invalid_environment',
        message: `Environment ${environmentId} was not found for this organization`,
      });
      return false;
    }
    if (environment.status !== 'ACTIVE') {
      res.status(409).json({
        ok: false,
        code: 'environment_archived',
        message: `Environment ${environmentId} is archived and cannot be used for API keys`,
      });
      return false;
    }
    return true;
  } catch (error: unknown) {
    sendOrgProjectEnvError(res, error);
    return false;
  }
}

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

async function emitApprovalWebhookEvent(
  ctx: ExpressConsoleContext,
  input: {
    orgId: string;
    actorUserId: string;
    eventType: 'policy.approval.created' | 'policy.approval.approved' | 'policy.approval.rejected';
    payload: Record<string, unknown>;
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
        eventType: input.eventType,
        payload: input.payload,
      },
    );
  } catch (error: unknown) {
    ctx.logger.warn('[console][webhooks] failed to emit approval event', {
      eventType: input.eventType,
      orgId: input.orgId,
      message: error instanceof Error ? error.message : String(error),
    });
  }
}

async function emitConsoleAuditEvent(
  ctx: ExpressConsoleContext,
  claims: ConsoleAuthClaims,
  input: {
    category:
      | 'POLICY'
      | 'SETTINGS'
      | 'KEY_EXPORT'
      | 'BILLING'
      | 'WEBHOOK'
      | 'API_KEY'
      | 'TEAM'
      | 'APPROVAL'
      | 'ORG_PROJECT_ENV'
      | 'RUNTIME_SNAPSHOT'
      | 'SYSTEM';
    action: string;
    summary: string;
    outcome?: 'SUCCESS' | 'FAILURE' | 'PENDING';
    actorUserId?: string;
    actorType?: 'USER' | 'SYSTEM';
    projectId?: string;
    environmentId?: string;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  if (!ctx.audit) return;
  try {
    await ctx.audit.appendEvent(toAuditContext(claims), {
      category: input.category,
      action: input.action,
      outcome: input.outcome || 'SUCCESS',
      summary: input.summary,
      ...(input.actorUserId ? { actorUserId: input.actorUserId } : {}),
      ...(input.actorType ? { actorType: input.actorType } : {}),
      ...(input.projectId ? { projectId: input.projectId } : {}),
      ...(input.environmentId ? { environmentId: input.environmentId } : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    });
  } catch (error: unknown) {
    ctx.logger.warn('[console][audit] failed to append audit event', {
      orgId: claims.orgId,
      userId: input.actorUserId || claims.userId,
      category: input.category,
      action: input.action,
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

function registerConsoleAccountRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/account/profile', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const account = requireAccountService(res, ctx);
    if (!account) return;
    try {
      const profile = await account.getProfile(toAccountContext(claims));
      res.status(200).json({ ok: true, profile });
    } catch (error: unknown) {
      sendAccountError(res, error);
    }
  });

  router.patch('/console/account/profile', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const account = requireAccountService(res, ctx);
    if (!account) return;
    try {
      const request = parsePatchConsoleAccountProfileRequest((req as any).body || {});
      const profile = await account.updateProfile(toAccountContext(claims), request);
      res.status(200).json({ ok: true, profile });
    } catch (error: unknown) {
      sendAccountError(res, error);
    }
  });

  router.get('/console/account/organizations', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const account = requireAccountService(res, ctx);
    if (!account) return;
    try {
      const organizations = await account.listOrganizations(toAccountContext(claims));
      res.status(200).json({ ok: true, organizations });
    } catch (error: unknown) {
      sendAccountError(res, error);
    }
  });

  router.post('/console/account/organizations', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const account = requireAccountService(res, ctx);
    if (!account) return;
    try {
      const request = parseCreateConsoleAccountOrganizationRequest((req as any).body || {});
      const organization = await account.createOrganization(toAccountContext(claims), request);
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'ORG_PROJECT_ENV',
        action: 'organization.create',
        summary: `Created organization ${organization.name || organization.id} from account settings`,
        metadata: {
          organizationId: organization.id,
          organizationName: organization.name,
          organizationSlug: organization.slug,
          source: 'account_settings',
        },
      });
      res.status(201).json({ ok: true, organization });
    } catch (error: unknown) {
      sendAccountError(res, error);
    }
  });

  router.patch('/console/account/organizations/:orgId', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const account = requireAccountService(res, ctx);
    if (!account) return;
    const orgId = readPathParam(req, 'orgId');
    if (!orgId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing organization id' });
      return;
    }
    try {
      const request = parseUpdateConsoleAccountOrganizationRequest((req as any).body || {});
      const organization = await account.updateOrganization(
        toAccountContext(claims),
        orgId,
        request,
      );
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'ORG_PROJECT_ENV',
        action: 'organization.update',
        summary: `Updated organization ${organization.name || organization.id} from account settings`,
        metadata: {
          organizationId: organization.id,
          organizationName: organization.name,
          organizationSlug: organization.slug,
          source: 'account_settings',
        },
      });
      res.status(200).json({ ok: true, organization });
    } catch (error: unknown) {
      sendAccountError(res, error);
    }
  });

  router.delete('/console/account/organizations/:orgId', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const account = requireAccountService(res, ctx);
    if (!account) return;
    const orgId = readPathParam(req, 'orgId');
    if (!orgId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing organization id' });
      return;
    }
    try {
      const deleted = await account.deleteOrganization(toAccountContext(claims), orgId);
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'ORG_PROJECT_ENV',
        action: 'organization.delete',
        summary: `Deleted organization ${deleted.organizationName || deleted.orgId} from account settings`,
        metadata: {
          organizationId: deleted.orgId,
          organizationName: deleted.organizationName,
          source: 'account_settings',
        },
      });
      res.status(200).json({ ok: true, deleted });
    } catch (error: unknown) {
      sendAccountError(res, error);
    }
  });

  router.post(
    '/console/account/organizations/:orgId/transfer-owner',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
      if (!routePolicy) return;
      const account = requireAccountService(res, ctx);
      if (!account) return;
      const orgId = readPathParam(req, 'orgId');
      if (!orgId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_path', message: 'Missing organization id' });
        return;
      }
      try {
        const request = parseTransferConsoleAccountOrganizationOwnerRequest(
          (req as any).body || {},
        );
        const transfer = await account.transferOrganizationOwner(
          toAccountContext(claims),
          orgId,
          request,
        );
        await emitConsoleAuditEvent(ctx, claims, {
          category: 'TEAM',
          action: 'member.owner.transfer',
          summary: `Transferred organization ${transfer.organization.id} ownership to ${transfer.nextOwner.userId}`,
          metadata: {
            organizationId: transfer.organization.id,
            previousOwnerUserId: transfer.previousOwner.userId,
            nextOwnerUserId: transfer.nextOwner.userId,
            source: 'account_settings',
          },
        });
        res.status(200).json({ ok: true, transfer });
      } catch (error: unknown) {
        sendAccountError(res, error);
      }
    },
  );

  router.post(
    '/console/account/organizations/:orgId/switch-context',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
      if (!routePolicy) return;
      const account = requireAccountService(res, ctx);
      if (!account) return;
      const session = requireSessionAdapter(res, ctx);
      if (!session) return;
      const orgId = readPathParam(req, 'orgId');
      if (!orgId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_path', message: 'Missing organization id' });
        return;
      }
      try {
        const nextContext = await account.switchOrganizationContext(
          toAccountContext(claims),
          orgId,
        );
        const parsedSession = await parseConsoleSessionForContextSwitch(
          session,
          (req as any).headers,
        );
        if (!parsedSession) {
          res.status(401).json({
            ok: false,
            code: 'unauthorized',
            message: 'A valid app session is required to switch organization context',
          });
          return;
        }
        const jwt = await session.signJwt(
          parsedSession.userId,
          buildConsoleContextSwitchSessionClaims(parsedSession.claims, nextContext),
        );
        res.set('Set-Cookie', session.buildSetCookie(jwt));
        res.status(200).json({ ok: true, context: nextContext });
      } catch (error: unknown) {
        sendAccountError(res, error);
      }
    },
  );
}

function registerConsoleOnboardingRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/onboarding/state', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const onboarding = requireOnboardingService(res, ctx);
    if (!onboarding) return;
    try {
      const request = parseGetConsoleOnboardingStateRequest((req as any).query || {});
      const state = await onboarding.getOnboardingState(toOnboardingContext(claims), request);
      res.status(200).json({ ok: true, state });
    } catch (error: unknown) {
      sendOnboardingError(res, error);
    }
  });

  router.get('/console/onboarding/telemetry', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const onboarding = requireOnboardingService(res, ctx);
    if (!onboarding) return;
    try {
      const request = parseGetConsoleOnboardingTelemetryRequest((req as any).query || {});
      const telemetry = await onboarding.getOnboardingTelemetry(
        toOnboardingContext(claims),
        request,
      );
      res.status(200).json({ ok: true, telemetry });
    } catch (error: unknown) {
      sendOnboardingError(res, error);
    }
  });

  router.post('/console/onboarding/organization', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const onboarding = requireOnboardingService(res, ctx);
    if (!onboarding) return;
    try {
      const request = parseCreateConsoleOnboardingOrganizationRequest((req as any).body || {});
      const result = await onboarding.createOnboardingOrganization(
        toOnboardingContext(claims),
        request,
      );
      if (result.created.owner) {
        await emitConsoleAuditEvent(ctx, claims, {
          category: 'TEAM',
          action: 'member.owner.bootstrap',
          summary: `Bootstrapped owner membership for user ${claims.userId} during onboarding organization step`,
          metadata: {
            onboarding: true,
            onboardingStep: 'organization',
            userId: claims.userId,
          },
        });
      }
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'ORG_PROJECT_ENV',
        action: 'organization.configure',
        summary: `Configured organization ${result.organization.id} via onboarding organization step`,
        metadata: {
          onboarding: true,
          onboardingStep: 'organization',
          organizationId: result.organization.id,
          organizationName: result.organization.name,
          organizationSlug: result.organization.slug,
          created: result.created.organization,
        },
      });
      const status = result.created.organization || result.created.owner ? 201 : 200;
      res.status(status).json({ ok: true, result });
    } catch (error: unknown) {
      sendOnboardingError(res, error);
    }
  });

  router.post('/console/onboarding/project', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const onboarding = requireOnboardingService(res, ctx);
    if (!onboarding) return;
    try {
      const request = parseCreateConsoleOnboardingProjectRequest((req as any).body || {});
      const result = await onboarding.createOnboardingProject(toOnboardingContext(claims), request);
      if (result.created.project) {
        await emitConsoleAuditEvent(ctx, claims, {
          category: 'ORG_PROJECT_ENV',
          action: 'project.create',
          summary: `Created project ${result.project.id} via onboarding project step`,
          projectId: result.project.id,
          metadata: {
            onboarding: true,
            projectId: result.project.id,
            onboardingStep: 'project',
          },
        });
      }
      if (result.created.environment) {
        await emitConsoleAuditEvent(ctx, claims, {
          category: 'ORG_PROJECT_ENV',
          action: 'environment.create',
          summary: `Created environment ${result.environment.id} via onboarding project step`,
          projectId: result.environment.projectId,
          environmentId: result.environment.id,
          metadata: {
            onboarding: true,
            projectId: result.environment.projectId,
            environmentId: result.environment.id,
            environmentKey: result.environment.key,
            onboardingStep: 'project',
          },
        });
      }
      const status = result.created.project || result.created.environment ? 201 : 200;
      res.status(status).json({ ok: true, result });
    } catch (error: unknown) {
      sendOnboardingError(res, error);
    }
  });
}

function registerConsoleOpsCockpitRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/ops-cockpit/summary', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    try {
      const telemetryRequest = parseGetConsoleOnboardingTelemetryRequest((req as any).query || {});
      const summary = await buildConsoleOpsCockpitSummary({
        claims,
        approvals: ctx.approvals,
        billing: ctx.billing,
        webhooks: ctx.webhooks,
        auditExports: ctx.auditExports,
        enterpriseIsolation: ctx.enterpriseIsolation,
        onboarding: ctx.onboarding,
        canViewOnboardingTelemetry:
          hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'ops'),
        telemetryWindowMinutes: telemetryRequest.windowMinutes,
        logger: ctx.logger,
      });
      res.status(200).json({ ok: true, summary });
    } catch (error: unknown) {
      sendOnboardingError(res, error);
    }
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
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const request = parseCreateConsoleProjectRequest((req as any).body || {});
      const liveEnvironmentsEnabled = ctx.opts.allowLiveEnvironmentBillingBypass
        ? true
        : ctx.billing
          ? (await getBillingLiveEnvironmentReadiness(ctx.billing, toBillingContext(claims)))
              .canUseLiveEnvironments
          : false;
      const project = await orgProjectEnv.createProject(toOrgProjectEnvContext(claims), {
        ...request,
        liveEnvironmentsEnabled,
      });
      res.status(201).json({ ok: true, project });
    } catch (error: unknown) {
      if (isConsoleBillingError(error)) {
        sendBillingError(res, error);
        return;
      }
      sendOrgProjectEnvError(res, error);
    }
  });

  router.patch('/console/projects/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
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
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
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
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const request = parseCreateConsoleEnvironmentRequest((req as any).body || {});
      if (request.key !== 'dev' && !ctx.opts.allowLiveEnvironmentBillingBypass) {
        if (!ctx.billing) {
          sendBillingError(
            res,
            new ConsoleBillingError(
              'billing_required_live_environment',
              409,
              LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE,
            ),
          );
          return;
        }
        await ensureBillingReadyForLiveEnvironment(ctx.billing, toBillingContext(claims));
      }
      const environment = await orgProjectEnv.createEnvironment(
        toOrgProjectEnvContext(claims),
        request,
      );
      res.status(201).json({ ok: true, environment });
    } catch (error: unknown) {
      if (isConsoleBillingError(error)) {
        sendBillingError(res, error);
        return;
      }
      sendOrgProjectEnvError(res, error);
    }
  });

  router.patch('/console/environments/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
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
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
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

function registerConsoleTeamRbacRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/members', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const teamRbac = requireTeamRbacService(res, ctx);
    if (!teamRbac) return;
    try {
      const request = parseListConsoleTeamMembersRequest((req as any).query || {});
      const members = await teamRbac.listMembers(toTeamRbacContext(claims), request);
      res.status(200).json({ ok: true, members });
    } catch (error: unknown) {
      sendTeamRbacError(res, error);
    }
  });

  router.post('/console/members/invite', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const teamRbac = requireTeamRbacService(res, ctx);
    if (!teamRbac) return;
    try {
      const request = parseInviteConsoleTeamMemberRequest((req as any).body || {});
      const member = await teamRbac.inviteMember(toTeamRbacContext(claims), request);
      res.status(201).json({ ok: true, member });
    } catch (error: unknown) {
      sendTeamRbacError(res, error);
    }
  });

  router.patch('/console/members/:id/roles', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const teamRbac = requireTeamRbacService(res, ctx);
    if (!teamRbac) return;
    const memberId = readPathParam(req, 'id');
    if (!memberId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing member id' });
      return;
    }
    try {
      const request = parseUpdateConsoleTeamMemberRolesRequest((req as any).body || {});
      const member = await teamRbac.updateMemberRoles(toTeamRbacContext(claims), memberId, request);
      if (!member) {
        res.status(404).json({
          ok: false,
          code: 'member_not_found',
          message: `Member ${memberId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, member });
    } catch (error: unknown) {
      sendTeamRbacError(res, error);
    }
  });

  router.delete('/console/members/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const teamRbac = requireTeamRbacService(res, ctx);
    if (!teamRbac) return;
    const memberId = readPathParam(req, 'id');
    if (!memberId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing member id' });
      return;
    }
    try {
      const out = await teamRbac.removeMember(toTeamRbacContext(claims), memberId);
      if (!out.removed || !out.member) {
        res.status(404).json({
          ok: false,
          code: 'member_not_found',
          message: `Member ${memberId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, removed: true, member: out.member });
    } catch (error: unknown) {
      sendTeamRbacError(res, error);
    }
  });
}

function registerConsoleApprovalRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/approvals', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const approvals = requireApprovalService(res, ctx);
    if (!approvals) return;
    try {
      const request = parseListConsoleApprovalsRequest((req as any).query || {});
      const rows = await approvals.listApprovalRequests(toApprovalContext(claims), request);
      res
        .status(200)
        .json({ ok: true, approvals: await projectApprovalResponses(ctx, claims, rows) });
    } catch (error: unknown) {
      sendApprovalError(res, error);
    }
  });

  router.get('/console/approvals/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const approvals = requireApprovalService(res, ctx);
    if (!approvals) return;
    const approvalId = readPathParam(req, 'id');
    if (!approvalId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing approval id' });
      return;
    }
    try {
      const row = await approvals.getApprovalRequest(toApprovalContext(claims), approvalId);
      if (!row) {
        res.status(404).json({
          ok: false,
          code: 'approval_not_found',
          message: `Approval request ${approvalId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, approval: await projectApprovalResponse(ctx, claims, row) });
    } catch (error: unknown) {
      sendApprovalError(res, error);
    }
  });

  router.post('/console/approvals', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const approvals = requireApprovalService(res, ctx);
    if (!approvals) return;
    try {
      const parsedRequest = parseCreateConsoleApprovalRequest((req as any).body || {});
      const request = await enrichPolicyApprovalCreateRequest(ctx, claims, parsedRequest);
      const row = await approvals.createApprovalRequest(toApprovalContext(claims), request);
      const approvalPolicy = projectConsolePolicyPresentation({
        resourceType: row.resourceType,
        resourceId: row.resourceId,
        metadata: row.metadata,
      });
      await emitApprovalWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'policy.approval.created',
        payload: {
          approvalId: row.id,
          operationType: row.operationType,
          status: row.status,
          requestedByUserId: row.requestedByUserId,
          requiredApprovals: row.requiredApprovals,
          requireMfa: row.requireMfa,
          projectId: row.projectId,
          environmentId: row.environmentId,
          resourceType: row.resourceType,
          resourceId: row.resourceId,
          policyId: approvalPolicy.policyId,
          policyName: approvalPolicy.policyName,
          policyKind: approvalPolicy.policyKind,
        },
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'APPROVAL',
        action: 'approval.request.create',
        summary: `Created approval request ${row.id} (${row.operationType})`,
        ...(row.projectId ? { projectId: row.projectId } : {}),
        ...(row.environmentId ? { environmentId: row.environmentId } : {}),
        metadata: {
          approvalId: row.id,
          operationType: row.operationType,
          status: row.status,
          requiredApprovals: row.requiredApprovals,
          requireMfa: row.requireMfa,
          ...(row.resourceType ? { resourceType: row.resourceType } : {}),
          ...(row.resourceId ? { resourceId: row.resourceId } : {}),
          ...(String(row.resourceType || '')
            .trim()
            .toUpperCase() === 'POLICY' && row.resourceId
            ? { policyId: row.resourceId }
            : {}),
          ...(approvalPolicy.policyKind ? { policyKind: approvalPolicy.policyKind } : {}),
        },
      });
      res.status(201).json({ ok: true, approval: await projectApprovalResponse(ctx, claims, row) });
    } catch (error: unknown) {
      sendApprovalError(res, error);
    }
  });

  router.post('/console/approvals/:id/approve', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const approvals = requireApprovalService(res, ctx);
    if (!approvals) return;
    const approvalId = readPathParam(req, 'id');
    if (!approvalId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing approval id' });
      return;
    }
    try {
      const request = parseApproveConsoleApprovalRequest((req as any).body || {});
      const row = await approvals.approveApprovalRequest(
        toApprovalContext(claims),
        approvalId,
        request,
      );
      if (!row) {
        res.status(404).json({
          ok: false,
          code: 'approval_not_found',
          message: `Approval request ${approvalId} was not found`,
        });
        return;
      }
      await emitApprovalWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'policy.approval.approved',
        payload: {
          approvalId: row.id,
          operationType: row.operationType,
          status: row.status,
          requiredApprovals: row.requiredApprovals,
          approvalsCount: row.decisions.filter((entry) => entry.decision === 'APPROVE').length,
          decisionsCount: row.decisions.length,
          resolvedAt: row.resolvedAt,
          projectId: row.projectId,
          environmentId: row.environmentId,
          resourceType: row.resourceType,
          resourceId: row.resourceId,
        },
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'APPROVAL',
        action: 'approval.request.approve',
        summary: `Approved approval request ${row.id} (${row.operationType})`,
        ...(row.projectId ? { projectId: row.projectId } : {}),
        ...(row.environmentId ? { environmentId: row.environmentId } : {}),
        metadata: {
          approvalId: row.id,
          operationType: row.operationType,
          status: row.status,
          approvalsCount: row.decisions.filter((entry) => entry.decision === 'APPROVE').length,
          decisionsCount: row.decisions.length,
          ...(row.resourceType ? { resourceType: row.resourceType } : {}),
          ...(row.resourceId ? { resourceId: row.resourceId } : {}),
          ...(String(row.resourceType || '')
            .trim()
            .toUpperCase() === 'POLICY' && row.resourceId
            ? { policyId: row.resourceId }
            : {}),
        },
      });
      res.status(200).json({ ok: true, approval: await projectApprovalResponse(ctx, claims, row) });
    } catch (error: unknown) {
      sendApprovalError(res, error);
    }
  });

  router.post('/console/approvals/:id/reject', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const approvals = requireApprovalService(res, ctx);
    if (!approvals) return;
    const approvalId = readPathParam(req, 'id');
    if (!approvalId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing approval id' });
      return;
    }
    try {
      const request = parseRejectConsoleApprovalRequest((req as any).body || {});
      const row = await approvals.rejectApprovalRequest(
        toApprovalContext(claims),
        approvalId,
        request,
      );
      if (!row) {
        res.status(404).json({
          ok: false,
          code: 'approval_not_found',
          message: `Approval request ${approvalId} was not found`,
        });
        return;
      }
      await emitApprovalWebhookEvent(ctx, {
        orgId: claims.orgId,
        actorUserId: claims.userId,
        eventType: 'policy.approval.rejected',
        payload: {
          approvalId: row.id,
          operationType: row.operationType,
          status: row.status,
          decisionsCount: row.decisions.length,
          resolvedAt: row.resolvedAt,
          projectId: row.projectId,
          environmentId: row.environmentId,
          resourceType: row.resourceType,
          resourceId: row.resourceId,
        },
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'APPROVAL',
        action: 'approval.request.reject',
        summary: `Rejected approval request ${row.id} (${row.operationType})`,
        ...(row.projectId ? { projectId: row.projectId } : {}),
        ...(row.environmentId ? { environmentId: row.environmentId } : {}),
        metadata: {
          approvalId: row.id,
          operationType: row.operationType,
          status: row.status,
          decisionsCount: row.decisions.length,
          ...(row.resourceType ? { resourceType: row.resourceType } : {}),
          ...(row.resourceId ? { resourceId: row.resourceId } : {}),
          ...(String(row.resourceType || '')
            .trim()
            .toUpperCase() === 'POLICY' && row.resourceId
            ? { policyId: row.resourceId }
            : {}),
        },
      });
      res.status(200).json({ ok: true, approval: await projectApprovalResponse(ctx, claims, row) });
    } catch (error: unknown) {
      sendApprovalError(res, error);
    }
  });
}

function registerConsoleAuditRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/audit/events', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const audit = requireAuditService(res, ctx);
    if (!audit) return;
    try {
      const request = parseListConsoleAuditEventsRequest((req as any).query || {});
      const events = await audit.listEvents(toAuditContext(claims), request);
      res.status(200).json({ ok: true, events: await projectAuditEventResponses(ctx, claims, events) });
    } catch (error: unknown) {
      sendAuditError(res, error);
    }
  });

  router.get('/console/audit/evidence', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const audit = requireAuditService(res, ctx);
    if (!audit) return;
    try {
      const request = parseListConsoleAuditEvidenceRequest((req as any).query || {});
      const evidence = await audit.listEvidence(toAuditContext(claims), request);
      res.status(200).json({ ok: true, evidence });
    } catch (error: unknown) {
      sendAuditError(res, error);
    }
  });
}

function registerConsoleAuditExportRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/audit/exports', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const auditExports = requireAuditExportsService(res, ctx);
    if (!auditExports) return;
    try {
      const request = parseListConsoleAuditExportsRequest((req as any).query || {});
      const exports = await auditExports.listExports(toAuditContext(claims), request);
      res.status(200).json({ ok: true, exports });
    } catch (error: unknown) {
      sendAuditExportsError(res, error);
    }
  });

  router.get('/console/audit/exports/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const auditExports = requireAuditExportsService(res, ctx);
    if (!auditExports) return;
    const exportId = readPathParam(req, 'id');
    if (!exportId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing export id' });
      return;
    }
    try {
      const auditExport = await auditExports.getExport(toAuditContext(claims), exportId);
      if (!auditExport) {
        res.status(404).json({
          ok: false,
          code: 'audit_export_not_found',
          message: `Audit export ${exportId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, export: auditExport });
    } catch (error: unknown) {
      sendAuditExportsError(res, error);
    }
  });

  router.post('/console/audit/exports', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const auditExports = requireAuditExportsService(res, ctx);
    if (!auditExports) return;
    try {
      const request = parseCreateConsoleAuditExportRequest((req as any).body || {});
      const auditExport = await auditExports.createExport(toAuditContext(claims), request);
      res.status(201).json({ ok: true, export: auditExport });
    } catch (error: unknown) {
      sendAuditExportsError(res, error);
    }
  });
}

function registerConsoleEnterpriseIsolationRoutes(
  router: ExpressRouter,
  ctx: ExpressConsoleContext,
): void {
  router.get('/console/isolation/status', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const enterpriseIsolation = requireEnterpriseIsolationService(res, ctx);
    if (!enterpriseIsolation) return;
    try {
      const request = parseGetConsoleEnterpriseIsolationRequest((req as any).query || {});
      const isolation = await enterpriseIsolation.getIsolationState(
        toAuditContext(claims),
        request,
      );
      res.status(200).json({ ok: true, isolation });
    } catch (error: unknown) {
      sendEnterpriseIsolationError(res, error);
    }
  });

  router.post('/console/isolation/trigger', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const enterpriseIsolation = requireEnterpriseIsolationService(res, ctx);
    if (!enterpriseIsolation) return;
    try {
      const request = parseTriggerConsoleEnterpriseIsolationRequest((req as any).body || {});
      const isolation = await enterpriseIsolation.triggerIsolation(toAuditContext(claims), request);
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'SYSTEM',
        action: 'enterprise_isolation.trigger',
        summary: `Triggered enterprise isolation (${isolation.scope})`,
        ...(isolation.projectId ? { projectId: isolation.projectId } : {}),
        ...(isolation.environmentId ? { environmentId: isolation.environmentId } : {}),
        metadata: {
          scope: isolation.scope,
          status: isolation.status,
          mode: isolation.mode,
          trigger: isolation.trigger,
          ticketId: isolation.ticketId,
        },
      });
      res.status(202).json({ ok: true, isolation });
    } catch (error: unknown) {
      sendEnterpriseIsolationError(res, error);
    }
  });
}

function registerConsoleWalletRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.get('/console/wallets', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
      const request = parseListConsolePoliciesRequest((req as any).query || {});
      const out = await policies.listPolicies(toBillingContext(claims), request);
      res.status(200).json({ ok: true, policies: out });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.get('/console/policies/:id/versions', async (req: Request, res: Response) => {
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
      const versions = await policies.listPolicyVersions(toBillingContext(claims), policyId);
      if (!versions) {
        res.status(404).json({
          ok: false,
          code: 'policy_not_found',
          message: `Policy ${policyId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, versions });
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
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    try {
      const request = parseCreateConsolePolicyRequest((req as any).body || {});
      const policy = await policies.createPolicy(toBillingContext(claims), request);
      const auditEvent = buildConsolePolicyAuditEvent({
        action: 'policy.create',
        policy,
        assignment: request.assignment,
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'POLICY',
        action: 'policy.create',
        summary: auditEvent.summary,
        ...(auditEvent.projectId ? { projectId: auditEvent.projectId } : {}),
        ...(auditEvent.environmentId ? { environmentId: auditEvent.environmentId } : {}),
        metadata: auditEvent.metadata,
      });
      res.status(201).json({ ok: true, policy });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.put('/console/policies/assignments', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    try {
      const request = parseUpsertConsolePolicyAssignmentRequest((req as any).body || {});
      const assignment = await policies.upsertAssignment(toBillingContext(claims), request);
      const policy = await policies.getPolicy(toBillingContext(claims), assignment.policyId);
      const auditEvent = buildConsolePolicyAssignmentAuditEvent({
        action: 'policy.assignment.upsert',
        assignment,
        policy,
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'POLICY',
        action: 'policy.assignment.upsert',
        summary: auditEvent.summary,
        ...(auditEvent.projectId ? { projectId: auditEvent.projectId } : {}),
        ...(auditEvent.environmentId ? { environmentId: auditEvent.environmentId } : {}),
        metadata: auditEvent.metadata,
      });
      res.status(200).json({ ok: true, assignment });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.delete('/console/policies/assignments/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
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
      const policy = await policies.getPolicy(toBillingContext(claims), out.assignment.policyId);
      const auditEvent = buildConsolePolicyAssignmentAuditEvent({
        action: 'policy.assignment.delete',
        assignment: out.assignment,
        policy,
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'POLICY',
        action: 'policy.assignment.delete',
        summary: auditEvent.summary,
        ...(auditEvent.projectId ? { projectId: auditEvent.projectId } : {}),
        ...(auditEvent.environmentId ? { environmentId: auditEvent.environmentId } : {}),
        metadata: auditEvent.metadata,
      });
      res.status(200).json({ ok: true, removed: true, assignment: out.assignment });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.patch('/console/policies/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
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
      const auditEvent = buildConsolePolicyAuditEvent({
        action: 'policy.update',
        policy,
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'POLICY',
        action: 'policy.update',
        summary: auditEvent.summary,
        ...(auditEvent.projectId ? { projectId: auditEvent.projectId } : {}),
        ...(auditEvent.environmentId ? { environmentId: auditEvent.environmentId } : {}),
        metadata: auditEvent.metadata,
      });
      res.status(200).json({ ok: true, policy });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.delete('/console/policies/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    const policyId = readPathParam(req, 'id');
    if (!policyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing policy id' });
      return;
    }
    try {
      const result = await policies.deletePolicy(toBillingContext(claims), policyId);
      if (!result.removed || !result.policy) {
        res.status(404).json({
          ok: false,
          code: 'policy_not_found',
          message: `Policy ${policyId} was not found`,
        });
        return;
      }
      const auditEvent = buildConsolePolicyAuditEvent({
        action: 'policy.delete',
        policy: result.policy,
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'POLICY',
        action: 'policy.delete',
        summary: auditEvent.summary,
        ...(auditEvent.projectId ? { projectId: auditEvent.projectId } : {}),
        ...(auditEvent.environmentId ? { environmentId: auditEvent.environmentId } : {}),
        metadata: auditEvent.metadata,
      });
      res.status(200).json({ ok: true, removed: true, policy: result.policy });
    } catch (error: unknown) {
      sendPolicyError(res, error);
    }
  });

  router.post('/console/policies/:id/publish', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
    const policies = requirePolicyService(res, ctx);
    if (!policies) return;
    const policyId = readPathParam(req, 'id');
    if (!policyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing policy id' });
      return;
    }
    let approvalIdForFailure: string | undefined;
    try {
      const rawBody = (req as any).body || {};
      approvalIdForFailure = readApprovalIdFromBody(rawBody);
      if (
        !(await requireApprovedOperationApproval(res, ctx, claims, {
          operationType: 'POLICY_PUBLISH',
          approvalIdRaw: approvalIdForFailure,
          resourceType: 'policy',
          resourceId: policyId,
        }))
      ) {
        return;
      }
      const result = await policies.publishPolicy(toBillingContext(claims), policyId);
      if (!result) {
        res.status(404).json({
          ok: false,
          code: 'policy_not_found',
          message: `Policy ${policyId} was not found`,
        });
        return;
      }
      const auditEvent = buildConsolePolicyAuditEvent({
        action: 'policy.publish',
        policy: result.policy,
        extraMetadata: {
          published: result.published,
        },
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'POLICY',
        action: 'policy.publish',
        summary: auditEvent.summary,
        ...(auditEvent.projectId ? { projectId: auditEvent.projectId } : {}),
        ...(auditEvent.environmentId ? { environmentId: auditEvent.environmentId } : {}),
        metadata: auditEvent.metadata,
      });
      res.status(200).json({ ok: true, result });
    } catch (error: unknown) {
      await emitApprovalFailureObservabilityEvent(ctx, req, claims, {
        approvalId: approvalIdForFailure,
        operationType: 'POLICY_PUBLISH',
        resourceType: 'policy',
        resourceId: policyId,
        error,
      });
      sendPolicyError(res, error);
    }
  });

  router.post('/console/policies/:id/simulate', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const routePolicy = requireConsoleRoutePolicy(req, res, ctx, claims);
    if (!routePolicy) return;
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
              resolveWalletPolicies: async (walletRows) =>
                await resolveWalletPolicyPresentationByWalletId(ctx, claims, walletRows),
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
        ...(ctx.policies
          ? {
              resolveWalletPolicies: async (walletRows) =>
                await resolveWalletPolicyPresentationByWalletId(ctx, claims, walletRows),
            }
          : {}),
      });
      res.status(200).json({ ok: true, readiness });
    } catch (error: unknown) {
      sendWalletError(res, error);
    }
  });

  router.get('/console/export/governance', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    const keyExports = requireKeyExportService(res, ctx);
    if (!keyExports) return;
    const environmentIdRaw = String((req as any)?.query?.environmentId || '').trim();
    const environmentIdFilter = environmentIdRaw || claims.environmentId || undefined;
    try {
      const governance = await buildConsoleExportGovernanceView({
        keyExports,
        keyExportCtx: toBillingContext(claims),
        environmentIdFilter,
      });
      res.status(200).json({ ok: true, governance });
    } catch (error: unknown) {
      sendKeyExportError(res, error);
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const keyExports = requireKeyExportService(res, ctx);
    if (!keyExports) return;
    const exportId = readPathParam(req, 'id');
    if (!exportId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing key export id' });
      return;
    }
    try {
      const rawBody = (req as any).body;
      if (
        !(await requireApprovedOperationApproval(res, ctx, claims, {
          operationType: 'KEY_EXPORT',
          approvalIdRaw: readApprovalIdFromBody(rawBody),
          resourceType: 'key_export',
          resourceId: exportId,
        }))
      ) {
        return;
      }
      const request = parseApproveConsoleKeyExportRequest(rawBody);
      const keyExport = await keyExports.approveKeyExport(
        toBillingContext(claims),
        exportId,
        request,
      );
      if (!keyExport) {
        res.status(404).json({
          ok: false,
          code: 'key_export_not_found',
          message: `Key export request ${exportId} was not found`,
        });
        return;
      }
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'KEY_EXPORT',
        action: 'key_export.approve',
        summary: `Approved key export request ${keyExport.id}`,
        ...(keyExport.environmentId ? { environmentId: keyExport.environmentId } : {}),
        metadata: {
          keyExportId: keyExport.id,
          status: keyExport.status,
          mode: keyExport.mode,
          approvedByUserId: claims.userId,
        },
      });
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
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    try {
      const request = parseCreateConsoleApiKeyRequest((req as any).body);
      const validEnvironment = await requireActiveApiKeyEnvironmentForCreate(
        res,
        ctx,
        claims,
        request.environmentId,
      );
      if (!validEnvironment) return;
      const created = await apiKeys.createApiKey(toBillingContext(claims), request);
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'API_KEY',
        action: 'api_key.create',
        summary: `Created API key ${created.apiKey.id}`,
        environmentId: created.apiKey.environmentId,
        metadata: {
          apiKeyId: created.apiKey.id,
          kind: created.apiKey.kind,
          scopeCount: Array.isArray(created.apiKey.scopes) ? created.apiKey.scopes.length : 0,
          ipAllowlistCount: Array.isArray(created.apiKey.ipAllowlist)
            ? created.apiKey.ipAllowlist.length
            : 0,
          allowedOriginCount: Array.isArray(created.apiKey.allowedOrigins)
            ? created.apiKey.allowedOrigins.length
            : 0,
        },
      });
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    const apiKeyId = readPathParam(req, 'id');
    if (!apiKeyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing API key id' });
      return;
    }
    try {
      const request = parseRevokeConsoleApiKeyRequest((req as any).body);
      const revoked = await apiKeys.revokeApiKey(toBillingContext(claims), apiKeyId, request);
      if (!revoked.revoked || !revoked.apiKey) {
        res.status(404).json({
          ok: false,
          code: 'api_key_not_found',
          message: `API key ${apiKeyId} was not found`,
        });
        return;
      }
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'API_KEY',
        action: 'api_key.revoke',
        summary: `Revoked API key ${revoked.apiKey.id}`,
        environmentId: revoked.apiKey.environmentId,
        metadata: {
          apiKeyId: revoked.apiKey.id,
          status: revoked.apiKey.status,
          revokedReason: revoked.apiKey.revokedReason,
        },
      });
      res.status(200).json({ ok: true, revoked: true, apiKey: revoked.apiKey });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });

  router.delete('/console/api-keys/:id/purge', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    const apiKeyId = readPathParam(req, 'id');
    if (!apiKeyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing API key id' });
      return;
    }
    try {
      const deleted = await apiKeys.deleteApiKey(toBillingContext(claims), apiKeyId);
      if (!deleted.deleted || !deleted.apiKey) {
        res.status(404).json({
          ok: false,
          code: 'api_key_not_found',
          message: `API key ${apiKeyId} was not found`,
        });
        return;
      }
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'API_KEY',
        action: 'api_key.delete',
        summary: `Deleted API key ${deleted.apiKey.id}`,
        environmentId: deleted.apiKey.environmentId,
        metadata: {
          apiKeyId: deleted.apiKey.id,
          kind: deleted.apiKey.kind,
          priorStatus: deleted.apiKey.status,
        },
      });
      res.status(200).json({ ok: true, deleted: true, apiKey: deleted.apiKey });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });

  router.patch('/console/api-keys/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const apiKeys = requireApiKeyService(res, ctx);
    if (!apiKeys) return;
    const apiKeyId = readPathParam(req, 'id');
    if (!apiKeyId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing API key id' });
      return;
    }
    try {
      const request = parseUpdateConsoleApiKeyRequest((req as any).body);
      const updated = await apiKeys.updateApiKey(toBillingContext(claims), apiKeyId, request);
      if (!updated) {
        res.status(404).json({
          ok: false,
          code: 'api_key_not_found',
          message: `API key ${apiKeyId} was not found`,
        });
        return;
      }
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'API_KEY',
        action: 'api_key.update',
        summary: `Updated API key ${updated.id}`,
        environmentId: updated.environmentId,
        metadata: {
          apiKeyId: updated.id,
          kind: updated.kind,
          scopeCount: Array.isArray(updated.scopes) ? updated.scopes.length : 0,
          ipAllowlistCount: Array.isArray(updated.ipAllowlist) ? updated.ipAllowlist.length : 0,
          allowedOriginCount: Array.isArray(updated.allowedOrigins)
            ? updated.allowedOrigins.length
            : 0,
        },
      });
      res.status(200).json({ ok: true, apiKey: updated });
    } catch (error: unknown) {
      sendApiKeyError(res, error);
    }
  });

  router.post('/console/api-keys/:id/rotate', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'API_KEY',
        action: 'api_key.rotate',
        summary: `Rotated API key ${rotated.apiKey.id} to version ${rotated.apiKey.secretVersion}`,
        environmentId: rotated.apiKey.environmentId,
        metadata: {
          apiKeyId: rotated.apiKey.id,
          kind: rotated.apiKey.kind,
          secretVersion: rotated.apiKey.secretVersion,
        },
      });
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const webhooks = requireWebhookService(res, ctx);
    if (!webhooks) return;
    try {
      const request = parseCreateConsoleWebhookEndpointRequest((req as any).body);
      const endpoint = await webhooks.createEndpoint(toBillingContext(claims), request);
      const auditEvent = buildConsoleWebhookEndpointAuditEvent({
        action: 'webhook.endpoint.create',
        endpoint,
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'WEBHOOK',
        action: 'webhook.endpoint.create',
        summary: auditEvent.summary,
        metadata: auditEvent.metadata,
      });
      res.status(201).json({ ok: true, endpoint });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.patch('/console/webhooks/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
      const auditEvent = buildConsoleWebhookEndpointAuditEvent({
        action: 'webhook.endpoint.update',
        endpoint,
      });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'WEBHOOK',
        action: 'webhook.endpoint.update',
        summary: auditEvent.summary,
        metadata: auditEvent.metadata,
      });
      res.status(200).json({ ok: true, endpoint });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });

  router.delete('/console/webhooks/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
      if (out.endpoint) {
        const auditEvent = buildConsoleWebhookEndpointAuditEvent({
          action: 'webhook.endpoint.delete',
          endpoint: out.endpoint,
        });
        await emitConsoleAuditEvent(ctx, claims, {
          category: 'WEBHOOK',
          action: 'webhook.endpoint.delete',
          summary: auditEvent.summary,
          metadata: auditEvent.metadata,
        });
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
      if (replay.delivery) {
        const auditEvent = buildConsoleWebhookReplayAuditEvent({
          endpointId,
          delivery: replay.delivery,
          requestedDeliveryId: request.deliveryId,
        });
        await emitConsoleAuditEvent(ctx, claims, {
          category: 'WEBHOOK',
          action: 'webhook.delivery.replay_requested',
          summary: auditEvent.summary,
          metadata: auditEvent.metadata,
        });
      }
      res.status(200).json({ ok: true, replay });
    } catch (error: unknown) {
      sendWebhookError(res, error);
    }
  });
}

function registerConsoleBillingRoutes(router: ExpressRouter, ctx: ExpressConsoleContext): void {
  router.post('/console/billing/stripe/webhook', async (req: Request, res: Response) => {
    const rawBody = (req as any).body;
    if (!requireStripeWebhookSecret(req, res, ctx)) {
      if (Number((res as any).statusCode || 0) === 401) {
        await emitStripeWebhookFailureObservabilityEvent(ctx, req, {
          rawBody,
          eventType: 'billing.stripe_webhook.invalid_signature',
          failureCode: 'invalid_signature',
          failureMessage: 'Invalid Stripe webhook secret',
        });
      }
      return;
    }
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseStripeWebhookEventRequest(rawBody);
      const result = await billing.processStripeWebhookEvent(request);
      if (result.accepted && result.purchase && result.orgId) {
        await emitBillingWebhookEvent(ctx, {
          orgId: result.orgId,
          actorUserId: 'system-stripe-webhook',
          eventType: 'billing.credit_purchase.settled',
          eventId: request.eventId,
          payload: {
            purchaseId: result.purchase.id,
            creditPackId: result.purchase.creditPackId,
            amountMinor: result.purchase.amountMinor,
            receiptId: result.invoice?.id || null,
            source: 'stripe_webhook',
          },
        });
        const auditEvent = buildConsoleBillingCreditPurchaseSettledAuditEvent({
          purchase: result.purchase,
          invoice: result.invoice,
          source: 'stripe_webhook',
          settlementEventId: request.eventId,
        });
        await emitConsoleAuditEvent(
          ctx,
          {
            orgId: result.orgId,
            userId: 'system-stripe-webhook',
            roles: ['ops'],
          },
          {
            category: 'BILLING',
            action: 'billing.credit_purchase.settled',
            summary: auditEvent.summary,
            actorUserId: 'system-stripe-webhook',
            actorType: 'SYSTEM',
            metadata: auditEvent.metadata,
          },
        );
      }
      res.status(200).json({ ok: true, ...result });
    } catch (error: unknown) {
      await emitStripeWebhookFailureObservabilityEvent(ctx, req, {
        rawBody,
        eventType: 'billing.stripe_webhook.processing.failed',
        failureCode: isConsoleBillingError(error) ? error.code : 'internal',
        failureMessage: error instanceof Error ? error.message : String(error),
      });
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/overview', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const overview = await buildConsoleBillingOverviewResponse(ctx, claims, billing);
      res.status(200).json({ ok: true, overview });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/account/activity', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseBillingAccountActivityRequest((req as any).query);
      const activity = await billing.listAccountActivity(toBillingContext(claims), request);
      res.status(200).json({ ok: true, activity });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/sponsored-executions', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const sponsoredCalls = requireSponsoredCallService(res, ctx);
    if (!sponsoredCalls) return;
    try {
      const request = parseListConsoleSponsoredCallRecordsRequest((req as any).query);
      const page = await sponsoredCalls.listRecords(toBillingContext(claims), request);
      res.status(200).json({ ok: true, page });
    } catch (error: unknown) {
      sendSponsoredCallError(res, error);
    }
  });

  router.get('/console/billing/sponsored-executions/reconciliation', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const sponsoredCalls = requireSponsoredCallService(res, ctx);
    if (!sponsoredCalls) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseListConsoleSponsoredCallRecordsRequest((req as any).query);
      const page = await listConsoleSponsoredCallReconciliationPage({
        sponsoredCalls,
        billing,
        ctx: toBillingContext(claims),
        request,
      });
      res.status(200).json({ ok: true, page });
    } catch (error: unknown) {
      if (isConsoleSponsoredCallError(error)) {
        sendSponsoredCallError(res, error);
        return;
      }
      sendBillingError(res, error);
    }
  });

  router.get('/console/platform/billing/search', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    try {
      const organizations = await searchPlatformBillingOrganizations({
        orgProjectEnv,
        request: parsePlatformBillingSearchRequest((req as any).query),
      });
      res.status(200).json({ ok: true, organizations });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/platform/billing/account', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
    if (!orgProjectEnv) return;
    const teamRbac = requireTeamRbacService(res, ctx);
    if (!teamRbac) return;
    try {
      const request = parsePlatformBillingLookupRequest((req as any).query);
      const result = await resolvePlatformBillingLookup({
        claims,
        billing,
        orgProjectEnv,
        teamRbac,
        request,
      });
      res.status(200).json({ ok: true, result });
    } catch (error: unknown) {
      if (isConsoleOrgProjectEnvError(error)) {
        sendOrgProjectEnvError(res, error);
        return;
      }
      sendBillingError(res, error);
    }
  });

  router.get(
    '/console/billing/usage/monthly-active-wallets',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    let invoiceScopeId = 'monthly:unknown';
    try {
      const request = parseGenerateMonthlyInvoiceRequest((req as any).body);
      invoiceScopeId = `monthly:${request.periodMonthUtc}`;
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
      const auditEvent = buildConsoleBillingInvoiceGeneratedAuditEvent({ generation });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'BILLING',
        action: 'billing.invoice.generated',
        summary: auditEvent.summary,
        metadata: auditEvent.metadata,
      });
      res.status(200).json({ ok: true, generation });
    } catch (error: unknown) {
      await emitBillingFailureObservabilityEvent(ctx, req, claims, {
        operation: 'INVOICE_FINALIZATION',
        invoiceId: invoiceScopeId,
        error,
      });
      sendBillingError(res, error);
    }
  });

  router.post(
    '/console/billing/adjustments/support-credit',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      try {
        const request = parseBillingManualAdjustmentRequest((req as any).body);
        const billingCtx = toBillingContext(claims);
        const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(billing, billingCtx);
        const result = await billing.grantManualSupportCredit(billingCtx, request);
        await emitSponsorshipBalanceTransitionEvents({
        services: {
          logger: ctx.logger,
          webhooks: ctx.webhooks,
          observabilityIngestion: ctx.observabilityIngestion,
        },
          ctx: billingCtx,
          before: beforeBalanceState,
          billing,
          trigger: {
            kind: 'manual_support_credit',
            adjustmentId: result.adjustment.id,
            sourceEventId: result.adjustment.idempotencyKey,
          },
        });
        await emitConsoleAuditEvent(ctx, claims, {
          category: 'BILLING',
          action: 'billing.adjustment.support_credit',
          summary: `Appended manual support credit for org ${claims.orgId}`,
          metadata: {
            organizationId: claims.orgId,
            adjustmentId: result.adjustment.id,
            amountMinor: result.adjustment.amountMinor,
            resultingBalanceMinor: result.creditBalanceMinor,
            reasonCode: result.adjustment.reasonCode,
            note: result.adjustment.note,
            relatedInvoiceId: result.adjustment.relatedInvoiceId,
            idempotencyKey: result.adjustment.idempotencyKey,
            created: result.created,
          },
        });
        res.status(result.created ? 201 : 200).json({ ok: true, result });
      } catch (error: unknown) {
        sendBillingError(res, error);
      }
    },
  );

  router.post(
    '/console/platform/billing/adjustments/support-credit',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
      if (!orgProjectEnv) return;
      try {
        const request = parsePlatformBillingManualAdjustmentRequest((req as any).body);
        const { orgId, ...adjustmentRequest } = request;
        const organization = await orgProjectEnv.getOrganization({
          orgId,
          actorUserId: claims.userId,
          roles: claims.roles,
          ...(claims.projectId ? { projectId: claims.projectId } : {}),
          ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
        });
        const billingCtx = {
          orgId,
          actorUserId: claims.userId,
          roles: claims.roles,
        };
        const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(billing, billingCtx);
        const result = await billing.grantManualSupportCredit(billingCtx, adjustmentRequest);
        await emitSponsorshipBalanceTransitionEvents({
        services: {
          logger: ctx.logger,
          webhooks: ctx.webhooks,
          observabilityIngestion: ctx.observabilityIngestion,
        },
          ctx: billingCtx,
          before: beforeBalanceState,
          billing,
          trigger: {
            kind: 'manual_support_credit',
            adjustmentId: result.adjustment.id,
            sourceEventId: result.adjustment.idempotencyKey,
          },
        });
        await emitConsoleAuditEvent(
          ctx,
          {
            ...claims,
            orgId,
          },
          {
            category: 'BILLING',
            action: 'billing.adjustment.support_credit',
            summary: `Appended manual support credit for org ${orgId}`,
            metadata: {
              organizationId: orgId,
              organizationName: organization.name,
              adjustmentId: result.adjustment.id,
              amountMinor: result.adjustment.amountMinor,
              resultingBalanceMinor: result.creditBalanceMinor,
              reasonCode: result.adjustment.reasonCode,
              note: result.adjustment.note,
              relatedInvoiceId: result.adjustment.relatedInvoiceId,
              idempotencyKey: result.adjustment.idempotencyKey,
              created: result.created,
              platformBilling: true,
            },
          },
        );
        res.status(result.created ? 201 : 200).json({ ok: true, result });
      } catch (error: unknown) {
        if (isConsoleOrgProjectEnvError(error)) {
          sendOrgProjectEnvError(res, error);
          return;
        }
        sendBillingError(res, error);
      }
    },
  );

  router.post('/console/billing/adjustments/admin-debit', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      try {
        const request = parseBillingManualAdjustmentRequest((req as any).body);
        const billingCtx = toBillingContext(claims);
        const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(billing, billingCtx);
        const result = await billing.appendManualAdminDebit(billingCtx, request);
        await emitSponsorshipBalanceTransitionEvents({
        services: {
          logger: ctx.logger,
          webhooks: ctx.webhooks,
          observabilityIngestion: ctx.observabilityIngestion,
        },
          ctx: billingCtx,
          before: beforeBalanceState,
          billing,
          trigger: {
            kind: 'manual_admin_debit',
            adjustmentId: result.adjustment.id,
            sourceEventId: result.adjustment.idempotencyKey,
          },
        });
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'BILLING',
        action: 'billing.adjustment.admin_debit',
        summary: `Appended manual admin debit for org ${claims.orgId}`,
        metadata: {
          organizationId: claims.orgId,
          adjustmentId: result.adjustment.id,
          amountMinor: result.adjustment.amountMinor,
          resultingBalanceMinor: result.creditBalanceMinor,
          reasonCode: result.adjustment.reasonCode,
          note: result.adjustment.note,
          relatedInvoiceId: result.adjustment.relatedInvoiceId,
          idempotencyKey: result.adjustment.idempotencyKey,
          created: result.created,
        },
      });
      res.status(result.created ? 201 : 200).json({ ok: true, result });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.post(
    '/console/platform/billing/adjustments/admin-debit',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      const orgProjectEnv = requireOrgProjectEnvService(res, ctx);
      if (!orgProjectEnv) return;
      try {
        const request = parsePlatformBillingManualAdjustmentRequest((req as any).body);
        const { orgId, ...adjustmentRequest } = request;
        const organization = await orgProjectEnv.getOrganization({
          orgId,
          actorUserId: claims.userId,
          roles: claims.roles,
          ...(claims.projectId ? { projectId: claims.projectId } : {}),
          ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
        });
        const billingCtx = {
          orgId,
          actorUserId: claims.userId,
          roles: claims.roles,
        };
        const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(billing, billingCtx);
        const result = await billing.appendManualAdminDebit(
          billingCtx,
          adjustmentRequest,
        );
        await emitSponsorshipBalanceTransitionEvents({
        services: {
          logger: ctx.logger,
          webhooks: ctx.webhooks,
          observabilityIngestion: ctx.observabilityIngestion,
        },
          ctx: billingCtx,
          before: beforeBalanceState,
          billing,
          trigger: {
            kind: 'manual_admin_debit',
            adjustmentId: result.adjustment.id,
            sourceEventId: result.adjustment.idempotencyKey,
          },
        });
        await emitConsoleAuditEvent(
          ctx,
          {
            ...claims,
            orgId,
          },
          {
            category: 'BILLING',
            action: 'billing.adjustment.admin_debit',
            summary: `Appended manual admin debit for org ${orgId}`,
            metadata: {
              organizationId: orgId,
              organizationName: organization.name,
              adjustmentId: result.adjustment.id,
              amountMinor: result.adjustment.amountMinor,
              resultingBalanceMinor: result.creditBalanceMinor,
              reasonCode: result.adjustment.reasonCode,
              note: result.adjustment.note,
              relatedInvoiceId: result.adjustment.relatedInvoiceId,
              idempotencyKey: result.adjustment.idempotencyKey,
              created: result.created,
              platformBilling: true,
            },
          },
        );
        res.status(result.created ? 201 : 200).json({ ok: true, result });
      } catch (error: unknown) {
        if (isConsoleOrgProjectEnvError(error)) {
          sendOrgProjectEnvError(res, error);
          return;
        }
        sendBillingError(res, error);
      }
    },
  );

  router.get('/console/billing/invoices', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    try {
      const request = parseBillingInvoiceListRequest((req as any).query);
      const page = await billing.listInvoicesPage(toBillingContext(claims), request);
      res.status(200).json({
        ok: true,
        invoices: page.invoices,
        nextCursor: page.nextCursor,
        totalCount: page.totalCount,
        summary: page.summary,
      });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/invoices/:id', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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

  router.get('/console/billing/invoices/:id/pdf', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
      await emitConsoleAuditEvent(ctx, claims, {
        category: 'BILLING',
        action: 'billing.invoice.pdf_export',
        summary: `Exported billing document PDF for ${invoice.id}`,
        metadata: {
          invoiceId: invoice.id,
          invoiceStatus: invoice.status,
          periodMonthUtc: invoice.periodMonthUtc,
          exportPolicy: CONSOLE_BILLING_INVOICE_PDF_EXPORT_POLICY,
        },
      });
      const pdf = buildConsoleBillingInvoicePdf({
        orgId: claims.orgId,
        invoice,
        lineItems,
      });
      res
        .status(200)
        .set('Content-Type', 'application/pdf')
        .set(
          'Content-Disposition',
          `attachment; filename="${buildConsoleBillingInvoicePdfFilename(invoice)}"`,
        )
        .send(Buffer.from(pdf));
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/invoices/:id/activity', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
    const billing = requireBillingService(res, ctx);
    if (!billing) return;
    const invoiceId = readPathParam(req, 'id');
    if (!invoiceId) {
      res.status(400).json({ ok: false, code: 'invalid_path', message: 'Missing invoice id' });
      return;
    }
    try {
      const activity = await billing.getInvoiceActivity(toBillingContext(claims), invoiceId);
      if (!activity) {
        res.status(404).json({
          ok: false,
          code: 'invoice_not_found',
          message: `Invoice ${invoiceId} was not found`,
        });
        return;
      }
      res.status(200).json({ ok: true, activity });
    } catch (error: unknown) {
      sendBillingError(res, error);
    }
  });

  router.get('/console/billing/invoices/:id/line-items', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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

  router.post('/console/billing/stripe/checkout-session', async (req: Request, res: Response) => {
    const claims = await requireConsoleAuth(req, res, ctx);
    if (!claims) return;
    if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
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
    '/console/billing/stripe/checkout-session/reconcile',
    async (req: Request, res: Response) => {
      const claims = await requireConsoleAuth(req, res, ctx);
      if (!claims) return;
      if (!requireConsoleRoutePolicy(req, res, ctx, claims)) return;
      const billing = requireBillingService(res, ctx);
      if (!billing) return;
      let checkoutSessionId = '';
      try {
        const request = parseStripeCheckoutSessionReconcileRequest((req as any).body);
        checkoutSessionId = request.checkoutSessionId;
        const billingCtx = toBillingContext(claims);
        const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(billing, billingCtx);
        const result = await billing.reconcileStripeCheckoutSession(
          billingCtx,
          request,
        );
        if (result.settledNow) {
          await emitSponsorshipBalanceTransitionEvents({
          services: {
            logger: ctx.logger,
            webhooks: ctx.webhooks,
            observabilityIngestion: ctx.observabilityIngestion,
          },
            ctx: billingCtx,
            before: beforeBalanceState,
            billing,
            trigger: {
              kind: 'credit_purchase_settled',
              purchaseId: result.purchase?.id || null,
              sourceEventId: request.checkoutSessionId,
            },
          });
        }
        if (result.settledNow && result.purchase && result.orgId) {
          await emitBillingWebhookEvent(ctx, {
            orgId: result.orgId,
            actorUserId: 'system-stripe-checkout-reconcile',
            eventType: 'billing.credit_purchase.settled',
            eventId: `stripe_checkout_reconcile:${request.checkoutSessionId}`,
            payload: {
              purchaseId: result.purchase.id,
              creditPackId: result.purchase.creditPackId,
              amountMinor: result.purchase.amountMinor,
              receiptId: result.invoice?.id || null,
              source: 'stripe_checkout_reconcile',
            },
          });
          const auditEvent = buildConsoleBillingCreditPurchaseSettledAuditEvent({
            purchase: result.purchase,
            invoice: result.invoice,
            source: 'stripe_checkout_reconcile',
            settlementEventId: `stripe_checkout_reconcile:${request.checkoutSessionId}`,
          });
          await emitConsoleAuditEvent(ctx, claims, {
            category: 'BILLING',
            action: 'billing.credit_purchase.settled',
            summary: auditEvent.summary,
            metadata: auditEvent.metadata,
          });
        }
        res.status(200).json({ ok: true, result });
      } catch (error: unknown) {
        await emitBillingFailureObservabilityEvent(ctx, req, claims, {
          operation: 'PAYMENT_RECONCILE',
          ...(checkoutSessionId ? { providerRef: checkoutSessionId } : {}),
          error,
        });
        sendBillingError(res, error);
      }
    },
  );
}

export function createConsoleRouter(opts: ConsoleRouterOptions = {}): ExpressRouter {
  const router = express.Router();
  const logger = coerceRouterLogger(opts.logger);
  const routeSurface = resolveConsoleRouteSurface();
  const { routeDefinitions } = routeSurface;
  const billing = opts.billing === undefined ? null : opts.billing;
  const prepaidReservations =
    opts.prepaidReservations === undefined ? null : opts.prepaidReservations;
  const sponsoredCalls = opts.sponsoredCalls === undefined ? null : opts.sponsoredCalls;
  const orgProjectEnv = opts.orgProjectEnv === undefined ? null : opts.orgProjectEnv;
  const wallets = opts.wallets === undefined ? null : opts.wallets;
  const policies = opts.policies === undefined ? null : opts.policies;
  const apiKeys = opts.apiKeys === undefined ? null : opts.apiKeys;
  const webhooks = opts.webhooks === undefined ? null : opts.webhooks;
  const keyExports = opts.keyExports === undefined ? null : opts.keyExports;
  const runtimeSnapshots = opts.runtimeSnapshots === undefined ? null : opts.runtimeSnapshots;
  const teamRbac = opts.teamRbac === undefined ? null : opts.teamRbac;
  const approvals = opts.approvals === undefined ? null : opts.approvals;
  const audit = opts.audit === undefined ? null : opts.audit;
  const auditExports = opts.auditExports === undefined ? null : opts.auditExports;
  const enterpriseIsolation =
    opts.enterpriseIsolation === undefined ? null : opts.enterpriseIsolation;
  const onboarding = opts.onboarding === undefined ? null : opts.onboarding;
  const account = opts.account === undefined ? null : opts.account;
  const observability = opts.observability === undefined ? null : opts.observability;
  const observabilityIngestion =
    opts.observabilityIngestion === undefined ? null : opts.observabilityIngestion;

  installConsoleCors(router, opts);

  const ctx: ExpressConsoleContext = {
    opts,
    logger,
    routeDefinitions,
    billing,
    prepaidReservations,
    sponsoredCalls,
    orgProjectEnv,
    wallets,
    policies,
    apiKeys,
    webhooks,
    keyExports,
    runtimeSnapshots,
    teamRbac,
    approvals,
    audit,
    auditExports,
    enterpriseIsolation,
    onboarding,
    account,
    observability,
    observabilityIngestion,
  };
  installConsoleObservabilityTiming(router, ctx);

  registerConsoleHealthRoutes(router, ctx);
  registerConsoleSessionRoute(router, ctx);
  registerConsoleAccountRoutes(router, ctx);
  registerConsoleOnboardingRoutes(router, ctx);
  registerConsoleOpsCockpitRoutes(router, ctx);
  registerConsoleObservabilityRoutes(router, ctx, {
    requireConsoleAuth,
    requireConsoleRoutePolicy: (req, res, routeCtx, claims) =>
      Boolean(requireConsoleRoutePolicy(req, res, routeCtx as ExpressConsoleContext, claims)),
    requireObservabilityService,
    toAuditContext,
    sendObservabilityError,
  });
  registerConsoleOrgProjectEnvRoutes(router, ctx);
  registerConsoleTeamRbacRoutes(router, ctx);
  registerConsoleApprovalRoutes(router, ctx);
  registerConsoleAuditRoutes(router, ctx);
  registerConsoleAuditExportRoutes(router, ctx);
  registerConsoleEnterpriseIsolationRoutes(router, ctx);
  registerConsoleWalletRoutes(router, ctx);
  registerConsolePolicyRoutes(router, ctx);
  registerConsoleInsightsRoutes(router, ctx);
  registerConsoleKeyExportRoutes(router, ctx);
  registerConsoleRuntimeSnapshotRoutes(router, ctx);
  registerConsoleApiKeyRoutes(router, ctx);
  registerConsoleWebhookRoutes(router, ctx);
  registerConsoleBillingRoutes(router, ctx);

  return attachConsoleRouteSurface(router, routeSurface);
}

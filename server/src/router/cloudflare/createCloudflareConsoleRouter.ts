import { buildCorsOrigins, normalizeCorsOrigin } from '../../core/SessionService';
import {
  buildConsoleBillingInvoicePdf,
  buildConsoleBillingInvoicePdfFilename,
  ConsoleBillingError,
  LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE,
  ensureBillingReadyForLiveEnvironment,
  isBillingReadyForLiveEnvironment,
  isConsoleBillingError,
  parseBillingInvoiceListRequest,
  parseAddCardPaymentMethodRequest,
  parseBillingUsageEventRequest,
  parseGenerateMonthlyInvoiceRequest,
  parseStripeWebhookEventRequest,
  parseStripeCustomerPortalSessionRequest,
  parseStripeCheckoutSessionRequest,
  parseStripeSetupIntentRequest,
  type ConsoleBillingService,
} from '../../console/billing';
import {
  isConsoleApiKeyError,
  parseCreateConsoleApiKeyRequest,
  parseRevokeConsoleApiKeyRequest,
  parseRotateConsoleApiKeyRequest,
  parseUpdateConsoleApiKeyRequest,
  type ConsoleApiKeyService,
} from '../../console/apiKeys';
import {
  parseCreateConsoleEnvironmentRequest,
  parseCreateConsoleProjectRequest,
  isConsoleOrgProjectEnvError,
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
  buildApprovalFailureObservabilityEvent,
  buildBillingFailureObservabilityEvent,
  buildRouterTimingObservabilityEvent,
  isConsoleObservabilityError,
  type ConsoleObservabilityIngestionService,
  type ConsoleObservabilityService,
} from '../../console/observability';
import type { ConsoleAuthClaims, ConsoleAuthResult, ConsoleRouterOptions } from '../console';
import { authenticateConsoleRequest, hasConsoleRole } from '../console';
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
import { resolveConsoleRuntimeSnapshotPayload } from '../runtimeSnapshotPayload';
import type { NormalizedRouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';
import { buildConsoleOpsCockpitSummary } from '../opsCockpitSummary';
import { handleConsoleObservabilityRoutes } from './consoleObservabilityRoutes';
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
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  wallets: ConsoleWalletService | null;
  policies: ConsolePolicyService | null;
  apiKeys: ConsoleApiKeyService | null;
  webhooks: ConsoleWebhookService | null;
  gasSponsorship: ConsoleGasSponsorshipService | null;
  smartWallets: ConsoleSmartWalletService | null;
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
  authClaims?: ConsoleAuthClaims;
}

const CONSOLE_CORS_ALLOW_HEADERS =
  'Content-Type,Authorization,X-Console-Org-Id,X-Console-User-Id,X-Console-Roles,X-Console-Project-Id,X-Console-Environment-Id,X-Console-Stripe-Webhook-Secret';

function withConsoleCors(headers: Headers, opts?: ConsoleRouterOptions, request?: Request): void {
  if (!opts?.corsOrigins) return;

  let allowedOrigin: string | '*' | undefined;
  const normalized = buildCorsOrigins(...(opts.corsOrigins || []));
  if (normalized === '*') {
    allowedOrigin = '*';
    headers.set('Access-Control-Allow-Origin', '*');
  } else if (Array.isArray(normalized)) {
    const originRaw = String(request?.headers.get('Origin') || '').trim();
    const originNormalized = normalizeCorsOrigin(originRaw);
    if (originRaw && originNormalized && normalized.includes(originNormalized)) {
      allowedOrigin = originRaw;
      headers.set('Access-Control-Allow-Origin', originRaw);
      headers.append('Vary', 'Origin');
    }
  }

  headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  headers.set('Access-Control-Allow-Headers', CONSOLE_CORS_ALLOW_HEADERS);
  if (allowedOrigin && allowedOrigin !== '*') {
    headers.set('Access-Control-Allow-Credentials', 'true');
  }
}

function readOptionalRequestHeader(request: Request, header: string): string | undefined {
  const value = String(request.headers.get(header) || '').trim();
  return value || undefined;
}

function toUnknownErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function appendConsoleObservabilityEvent(
  ctx: CloudflareConsoleContext,
  ingestCtx: Parameters<ConsoleObservabilityIngestionService['appendEvent']>[0],
  event: Parameters<ConsoleObservabilityIngestionService['appendEvent']>[1],
): Promise<void> {
  if (!ctx.observabilityIngestion) return;
  try {
    await ctx.observabilityIngestion.appendEvent(ingestCtx, event);
  } catch (error: unknown) {
    ctx.logger.warn('[console][observability] failed to append observability event', {
      orgId: ingestCtx.orgId,
      eventType: event.eventType,
      message: toUnknownErrorMessage(error),
    });
  }
}

async function emitRouterTimingObservabilityEvent(
  ctx: CloudflareConsoleContext,
  startedAtMs: number,
  statusCode: number,
): Promise<void> {
  const claims = ctx.authClaims;
  const roles = Array.isArray(claims?.roles) ? claims.roles.filter(Boolean) : [];
  const orgId = String(claims?.orgId || '').trim();
  if (!orgId) return;

  const requestId = readOptionalRequestHeader(ctx.request, 'x-request-id');
  const traceId =
    readOptionalRequestHeader(ctx.request, 'x-trace-id') ||
    readOptionalRequestHeader(ctx.request, 'traceparent');
  const event = buildRouterTimingObservabilityEvent({
    orgId,
    ...(claims?.projectId ? { projectId: claims.projectId } : {}),
    ...(claims?.environmentId ? { environmentId: claims.environmentId } : {}),
    route: ctx.pathname,
    method: ctx.method,
    statusCode,
    latencyMs: Math.max(0, Date.now() - startedAtMs),
    ...(requestId ? { requestId } : {}),
    ...(traceId ? { traceId } : {}),
  });
  await appendConsoleObservabilityEvent(
    ctx,
    {
      orgId,
      actorUserId: String(claims?.userId || 'system-console-router'),
      roles: roles.length ? roles : ['ops'],
      ...(claims?.projectId ? { projectId: claims.projectId } : {}),
      ...(claims?.environmentId ? { environmentId: claims.environmentId } : {}),
    },
    event,
  );
}

async function emitBillingFailureObservabilityEvent(
  ctx: CloudflareConsoleContext,
  claims: ConsoleAuthClaims,
  input: {
    operation: 'INVOICE_FINALIZATION';
    invoiceId?: string;
    providerRef?: string;
    error: unknown;
  },
): Promise<void> {
  const requestId = readOptionalRequestHeader(ctx.request, 'x-request-id');
  const traceId =
    readOptionalRequestHeader(ctx.request, 'x-trace-id') ||
    readOptionalRequestHeader(ctx.request, 'traceparent');
  const event = buildBillingFailureObservabilityEvent({
    orgId: claims.orgId,
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
    ...(input.invoiceId ? { invoiceId: input.invoiceId } : {}),
    operation: input.operation,
    failureCode: isConsoleBillingError(input.error) ? input.error.code : 'internal',
    failureMessage: toUnknownErrorMessage(input.error),
    ...(input.providerRef ? { providerRef: input.providerRef } : {}),
    ...(requestId ? { requestId } : {}),
    ...(traceId ? { traceId } : {}),
  });
  await appendConsoleObservabilityEvent(
    ctx,
    {
      orgId: claims.orgId,
      actorUserId: claims.userId,
      roles: claims.roles,
      ...(claims.projectId ? { projectId: claims.projectId } : {}),
      ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
    },
    event,
  );
}

async function emitApprovalFailureObservabilityEvent(
  ctx: CloudflareConsoleContext,
  claims: ConsoleAuthClaims,
  input: {
    approvalId?: string;
    operationType: string;
    resourceType?: string;
    resourceId?: string;
    error: unknown;
  },
): Promise<void> {
  const requestId = readOptionalRequestHeader(ctx.request, 'x-request-id');
  const traceId =
    readOptionalRequestHeader(ctx.request, 'x-trace-id') ||
    readOptionalRequestHeader(ctx.request, 'traceparent');
  const event = buildApprovalFailureObservabilityEvent({
    orgId: claims.orgId,
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
    ...(input.approvalId ? { approvalId: input.approvalId } : {}),
    operationType: input.operationType,
    ...(input.resourceType ? { resourceType: input.resourceType } : {}),
    ...(input.resourceId ? { resourceId: input.resourceId } : {}),
    failureCode: isConsolePolicyError(input.error) ? input.error.code : 'internal',
    failureMessage: toUnknownErrorMessage(input.error),
    ...(requestId ? { requestId } : {}),
    ...(traceId ? { traceId } : {}),
  });
  await appendConsoleObservabilityEvent(
    ctx,
    {
      orgId: claims.orgId,
      actorUserId: claims.userId,
      roles: claims.roles,
      ...(claims.projectId ? { projectId: claims.projectId } : {}),
      ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
    },
    event,
  );
}

function sendAuthFailure(auth: Extract<ConsoleAuthResult, { ok: false }>): Response {
  return json(
    {
      ok: false,
      code: auth.code,
      message: auth.message,
    },
    { status: auth.status },
  );
}

function sendBillingError(error: unknown): Response {
  if (isConsoleBillingError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendApiKeyError(error: unknown): Response {
  if (isConsoleApiKeyError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendOrgProjectEnvError(error: unknown): Response {
  if (isConsoleOrgProjectEnvError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendWalletError(error: unknown): Response {
  if (isConsoleWalletError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendPolicyError(error: unknown): Response {
  if (isConsolePolicyError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendWebhookError(error: unknown): Response {
  if (isConsoleWebhookError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendGasSponsorshipError(error: unknown): Response {
  if (isConsoleGasSponsorshipError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendSmartWalletError(error: unknown): Response {
  if (isConsoleSmartWalletError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendKeyExportError(error: unknown): Response {
  if (isConsoleKeyExportError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendRuntimeSnapshotError(error: unknown): Response {
  if (isConsoleRuntimeSnapshotError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendTeamRbacError(error: unknown): Response {
  if (isConsoleTeamRbacError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendApprovalError(error: unknown): Response {
  if (isConsoleApprovalsError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendAuditError(error: unknown): Response {
  if (isConsoleAuditError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendAuditExportsError(error: unknown): Response {
  if (isConsoleAuditExportsError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendEnterpriseIsolationError(error: unknown): Response {
  if (isConsoleEnterpriseIsolationError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendOnboardingError(error: unknown): Response {
  if (isConsoleOnboardingError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendObservabilityError(error: unknown): Response {
  if (isConsoleObservabilityError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }

  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

function sendAccountError(error: unknown): Response {
  if (isConsoleAccountError(error)) {
    return json(
      {
        ok: false,
        code: error.code,
        message: error.message,
        ...(error.details ? { details: error.details } : {}),
      },
      { status: error.status },
    );
  }
  return json(
    {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : String(error),
    },
    { status: 500 },
  );
}

async function requireConsoleAuth(
  ctx: CloudflareConsoleContext,
): Promise<{ ok: true; claims: ConsoleAuthClaims } | { ok: false; response: Response }> {
  const auth = await authenticateConsoleRequest(
    headersToRecord(ctx.request.headers),
    ctx.opts.auth,
  );
  if (!auth.ok) {
    return { ok: false, response: sendAuthFailure(auth) };
  }
  ctx.authClaims = auth.claims;
  return { ok: true, claims: auth.claims };
}

function requireBillingService(ctx: CloudflareConsoleContext): ConsoleBillingService | Response {
  if (ctx.billing) return ctx.billing;
  return json(
    {
      ok: false,
      code: 'billing_not_configured',
      message: 'Billing service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireApiKeyService(ctx: CloudflareConsoleContext): ConsoleApiKeyService | Response {
  if (ctx.apiKeys) return ctx.apiKeys;
  return json(
    {
      ok: false,
      code: 'api_keys_not_configured',
      message: 'API key service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireOrgProjectEnvService(
  ctx: CloudflareConsoleContext,
): ConsoleOrgProjectEnvService | Response {
  if (ctx.orgProjectEnv) return ctx.orgProjectEnv;
  return json(
    {
      ok: false,
      code: 'org_project_env_not_configured',
      message: 'Org/project/environment service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireWalletService(ctx: CloudflareConsoleContext): ConsoleWalletService | Response {
  if (ctx.wallets) return ctx.wallets;
  return json(
    {
      ok: false,
      code: 'wallets_not_configured',
      message: 'Wallet service is not configured on this server',
    },
    { status: 501 },
  );
}

function requirePolicyService(ctx: CloudflareConsoleContext): ConsolePolicyService | Response {
  if (ctx.policies) return ctx.policies;
  return json(
    {
      ok: false,
      code: 'policies_not_configured',
      message: 'Policy service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireWebhookService(ctx: CloudflareConsoleContext): ConsoleWebhookService | Response {
  if (ctx.webhooks) return ctx.webhooks;
  return json(
    {
      ok: false,
      code: 'webhooks_not_configured',
      message: 'Webhook service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireGasSponsorshipService(
  ctx: CloudflareConsoleContext,
): ConsoleGasSponsorshipService | Response {
  if (ctx.gasSponsorship) return ctx.gasSponsorship;
  return json(
    {
      ok: false,
      code: 'gas_sponsorship_not_configured',
      message: 'Gas sponsorship service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireSmartWalletService(
  ctx: CloudflareConsoleContext,
): ConsoleSmartWalletService | Response {
  if (ctx.smartWallets) return ctx.smartWallets;
  return json(
    {
      ok: false,
      code: 'smart_wallets_not_configured',
      message: 'Smart wallet service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireKeyExportService(
  ctx: CloudflareConsoleContext,
): ConsoleKeyExportService | Response {
  if (ctx.keyExports) return ctx.keyExports;
  return json(
    {
      ok: false,
      code: 'key_exports_not_configured',
      message: 'Key export service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireRuntimeSnapshotService(
  ctx: CloudflareConsoleContext,
): ConsoleRuntimeSnapshotService | Response {
  if (ctx.runtimeSnapshots) return ctx.runtimeSnapshots;
  return json(
    {
      ok: false,
      code: 'runtime_snapshots_not_configured',
      message: 'Runtime snapshot service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireTeamRbacService(ctx: CloudflareConsoleContext): ConsoleTeamRbacService | Response {
  if (ctx.teamRbac) return ctx.teamRbac;
  return json(
    {
      ok: false,
      code: 'team_rbac_not_configured',
      message: 'Team RBAC service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireApprovalService(ctx: CloudflareConsoleContext): ConsoleApprovalService | Response {
  if (ctx.approvals) return ctx.approvals;
  return json(
    {
      ok: false,
      code: 'approvals_not_configured',
      message: 'Approvals service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireAuditService(ctx: CloudflareConsoleContext): ConsoleAuditService | Response {
  if (ctx.audit) return ctx.audit;
  return json(
    {
      ok: false,
      code: 'audit_not_configured',
      message: 'Audit service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireAuditExportsService(
  ctx: CloudflareConsoleContext,
): ConsoleAuditExportsService | Response {
  if (ctx.auditExports) return ctx.auditExports;
  return json(
    {
      ok: false,
      code: 'audit_exports_not_configured',
      message: 'Audit exports service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireEnterpriseIsolationService(
  ctx: CloudflareConsoleContext,
): ConsoleEnterpriseIsolationService | Response {
  if (ctx.enterpriseIsolation) return ctx.enterpriseIsolation;
  return json(
    {
      ok: false,
      code: 'enterprise_isolation_not_configured',
      message: 'Enterprise isolation service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireOnboardingService(
  ctx: CloudflareConsoleContext,
): ConsoleOnboardingService | Response {
  if (ctx.onboarding) return ctx.onboarding;
  return json(
    {
      ok: false,
      code: 'onboarding_not_configured',
      message: 'Onboarding service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireAccountService(ctx: CloudflareConsoleContext): ConsoleAccountService | Response {
  if (ctx.account) return ctx.account;
  return json(
    {
      ok: false,
      code: 'account_not_configured',
      message: 'Account service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireSessionAdapter(ctx: CloudflareConsoleContext): NonNullable<ConsoleRouterOptions['session']> | Response {
  if (ctx.opts.session) return ctx.opts.session;
  return json(
    {
      ok: false,
      code: 'session_not_configured',
      message: 'Session adapter is not configured on this server',
    },
    { status: 501 },
  );
}

function requireObservabilityService(
  ctx: CloudflareConsoleContext,
): ConsoleObservabilityService | Response {
  if (ctx.observability) return ctx.observability;
  return json(
    {
      ok: false,
      code: 'observability_not_configured',
      message: 'Observability service is not configured on this server',
    },
    { status: 501 },
  );
}

function requireStripeWebhookSecret(ctx: CloudflareConsoleContext): Response | null {
  const configured = String(ctx.opts.billingStripeWebhookSecret || '').trim();
  if (!configured) {
    return json(
      {
        ok: false,
        code: 'stripe_webhook_not_configured',
        message: 'Stripe webhook secret is not configured on this server',
      },
      { status: 501 },
    );
  }
  const provided = String(ctx.request.headers.get('x-console-stripe-webhook-secret') || '').trim();
  if (!provided || provided !== configured) {
    return json(
      {
        ok: false,
        code: 'unauthorized',
        message: 'Invalid Stripe webhook secret',
      },
      { status: 401 },
    );
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
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
  };
}

function readApprovalIdFromBody(body: unknown): string {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return '';
  return String((body as Record<string, unknown>).approvalId || '').trim();
}

async function requireApprovedOperationApproval(
  ctx: CloudflareConsoleContext,
  claims: ConsoleAuthClaims,
  input: {
    operationType: ConsoleApprovalOperationType;
    approvalIdRaw: unknown;
    projectId?: string;
    environmentId?: string;
    resourceType?: string;
    resourceId?: string;
  },
): Promise<Response | null> {
  if (!ctx.approvals) return null;

  const approvalId = String(input.approvalIdRaw || '').trim();
  if (!approvalId) {
    return json(
      {
        ok: false,
        code: 'approval_required',
        message: `Field approvalId is required for ${input.operationType} when approvals service is configured`,
      },
      { status: 400 },
    );
  }

  let approval: Awaited<ReturnType<ConsoleApprovalService['getApprovalRequest']>> = null;
  try {
    approval = await ctx.approvals.getApprovalRequest(toApprovalContext(claims), approvalId);
  } catch (error: unknown) {
    return sendApprovalError(error);
  }

  if (!approval) {
    return json(
      {
        ok: false,
        code: 'approval_not_found',
        message: `Approval request ${approvalId} was not found`,
      },
      { status: 404 },
    );
  }

  if (approval.operationType !== input.operationType) {
    return json(
      {
        ok: false,
        code: 'approval_operation_mismatch',
        message: `Approval request ${approvalId} is ${approval.operationType}; expected ${input.operationType}`,
      },
      { status: 409 },
    );
  }

  if (approval.status !== 'APPROVED') {
    return json(
      {
        ok: false,
        code: 'approval_not_approved',
        message: `Approval request ${approvalId} is ${approval.status}; expected APPROVED`,
      },
      { status: 409 },
    );
  }

  const projectId = String(input.projectId || '').trim();
  if (projectId && approval.projectId && approval.projectId !== projectId) {
    return json(
      {
        ok: false,
        code: 'approval_scope_mismatch',
        message: `Approval request ${approvalId} project scope does not match request`,
      },
      { status: 409 },
    );
  }

  const environmentId = String(input.environmentId || '').trim();
  if (environmentId && approval.environmentId && approval.environmentId !== environmentId) {
    return json(
      {
        ok: false,
        code: 'approval_scope_mismatch',
        message: `Approval request ${approvalId} environment scope does not match request`,
      },
      { status: 409 },
    );
  }

  const resourceType = String(input.resourceType || '').trim();
  if (resourceType && approval.resourceType && approval.resourceType !== resourceType) {
    return json(
      {
        ok: false,
        code: 'approval_resource_mismatch',
        message: `Approval request ${approvalId} resource type does not match request`,
      },
      { status: 409 },
    );
  }

  const resourceId = String(input.resourceId || '').trim();
  if (resourceId && approval.resourceId && approval.resourceId !== resourceId) {
    return json(
      {
        ok: false,
        code: 'approval_resource_mismatch',
        message: `Approval request ${approvalId} resource id does not match request`,
      },
      { status: 409 },
    );
  }

  return null;
}

function requireAdminRoleForCardActions(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin')) return null;
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only admin can add, remove, or set default card payment methods',
    },
    { status: 403 },
  );
}

function requireInvoiceGenerationRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'ops')) return null;
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only admin or ops can generate monthly invoices',
    },
    { status: 403 },
  );
}

function requireOrgProjectEnvMutationRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'owner')) return null;
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only admin or owner can mutate projects and environments',
    },
    { status: 403 },
  );
}

function requireOnboardingTelemetryRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'ops')) return null;
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only admin or ops can view onboarding telemetry',
    },
    { status: 403 },
  );
}

function requireObservabilityReadRole(claims: ConsoleAuthClaims): Response | null {
  if (
    hasConsoleRole(claims, 'owner') ||
    hasConsoleRole(claims, 'admin') ||
    hasConsoleRole(claims, 'security_admin') ||
    hasConsoleRole(claims, 'ops') ||
    hasConsoleRole(claims, 'support')
  ) {
    return null;
  }
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only owner, admin, security_admin, ops, or support can view observability',
    },
    { status: 403 },
  );
}

function requireApiKeyMutationRole(claims: ConsoleAuthClaims): Response | null {
  if (
    hasConsoleRole(claims, 'owner') ||
    hasConsoleRole(claims, 'admin') ||
    hasConsoleRole(claims, 'security_admin')
  ) {
    return null;
  }
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only owner, admin, or security_admin can mutate API keys',
    },
    { status: 403 },
  );
}

function requireTeamRbacMutationRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin') || hasConsoleRole(claims, 'owner')) return null;
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only admin or owner can mutate org member roles',
    },
    { status: 403 },
  );
}

function requireApprovalMutationRole(claims: ConsoleAuthClaims): Response | null {
  if (
    hasConsoleRole(claims, 'owner') ||
    hasConsoleRole(claims, 'admin') ||
    hasConsoleRole(claims, 'security_admin')
  ) {
    return null;
  }
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only owner, admin, or security_admin can mutate approval queue requests',
    },
    { status: 403 },
  );
}

function requirePolicyMutationRole(claims: ConsoleAuthClaims): Response | null {
  if (
    hasConsoleRole(claims, 'owner') ||
    hasConsoleRole(claims, 'admin') ||
    hasConsoleRole(claims, 'security_admin')
  ) {
    return null;
  }
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only owner, admin, or security_admin can mutate policies',
    },
    { status: 403 },
  );
}

function requireConsoleConfigMutationRole(claims: ConsoleAuthClaims): Response | null {
  if (
    hasConsoleRole(claims, 'owner') ||
    hasConsoleRole(claims, 'admin') ||
    hasConsoleRole(claims, 'security_admin')
  ) {
    return null;
  }
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only owner, admin, or security_admin can mutate console configuration',
    },
    { status: 403 },
  );
}

function requireEnterpriseIsolationMutationRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'owner') || hasConsoleRole(claims, 'admin')) return null;
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only owner or admin can trigger enterprise isolation',
    },
    { status: 403 },
  );
}

function requireKeyExportApprovalRole(claims: ConsoleAuthClaims): Response | null {
  if (hasConsoleRole(claims, 'admin')) return null;
  return json(
    {
      ok: false,
      code: 'forbidden',
      message: 'Only admin can approve key export requests',
    },
    { status: 403 },
  );
}

async function requireActiveApiKeyEnvironmentForCreate(
  ctx: CloudflareConsoleContext,
  claims: ConsoleAuthClaims,
  environmentId: string,
): Promise<Response | null> {
  const orgProjectEnvOrResponse = requireOrgProjectEnvService(ctx);
  if (orgProjectEnvOrResponse instanceof Response) return orgProjectEnvOrResponse;
  try {
    const environments = await orgProjectEnvOrResponse.listEnvironments(
      toOrgProjectEnvContext(claims),
    );
    const environment = environments.find((entry) => entry.id === environmentId);
    if (!environment) {
      return json(
        {
          ok: false,
          code: 'invalid_environment',
          message: `Environment ${environmentId} was not found for this organization`,
        },
        { status: 400 },
      );
    }
    if (environment.status !== 'ACTIVE') {
      return json(
        {
          ok: false,
          code: 'environment_archived',
          message: `Environment ${environmentId} is archived and cannot be used for API keys`,
        },
        { status: 409 },
      );
    }
    return null;
  } catch (error: unknown) {
    return sendOrgProjectEnvError(error);
  }
}

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

async function emitApprovalWebhookEvent(
  ctx: CloudflareConsoleContext,
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
  ctx: CloudflareConsoleContext,
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
      ...(input.projectId ? { projectId: input.projectId } : {}),
      ...(input.environmentId ? { environmentId: input.environmentId } : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    });
  } catch (error: unknown) {
    ctx.logger.warn('[console][audit] failed to append audit event', {
      orgId: claims.orgId,
      userId: claims.userId,
      category: input.category,
      action: input.action,
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

  return json(
    {
      ok: true,
      service: 'console',
    },
    { status: 200 },
  );
}

async function handleConsoleReady(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!ctx.opts.readyz || ctx.method !== 'GET' || ctx.pathname !== '/console/readyz') return null;
  try {
    if (ctx.opts.readyCheck) {
      await ctx.opts.readyCheck();
    }
    return json(
      {
        ok: true,
        service: 'console',
      },
      { status: 200 },
    );
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'console_not_ready',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 503 },
    );
  }
}

async function handleConsoleSession(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (ctx.method !== 'GET' || ctx.pathname !== '/console/session') return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  return json(
    {
      ok: true,
      claims: auth.claims,
    },
    { status: 200 },
  );
}

async function handleConsoleAccount(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleAccountPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const accountOrResponse = requireAccountService(ctx);
  if (accountOrResponse instanceof Response) return accountOrResponse;
  const account = accountOrResponse;

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/account/profile') {
      const profile = await account.getProfile(toAccountContext(auth.claims));
      return json({ ok: true, profile }, { status: 200 });
    }

    if (ctx.method === 'PATCH' && ctx.pathname === '/console/account/profile') {
      const request = parsePatchConsoleAccountProfileRequest(await readJson(ctx.request));
      const profile = await account.updateProfile(toAccountContext(auth.claims), request);
      return json({ ok: true, profile }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/account/organizations') {
      const organizations = await account.listOrganizations(toAccountContext(auth.claims));
      return json({ ok: true, organizations }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/account/organizations') {
      const request = parseCreateConsoleAccountOrganizationRequest(await readJson(ctx.request));
      const organization = await account.createOrganization(toAccountContext(auth.claims), request);
      await emitConsoleAuditEvent(ctx, auth.claims, {
        category: 'ORG_PROJECT_ENV',
        action: 'organization.create',
        summary: `Created organization ${organization.id} from account settings`,
        metadata: {
          organizationId: organization.id,
          organizationName: organization.name,
          organizationSlug: organization.slug,
          source: 'account_settings',
        },
      });
      return json({ ok: true, organization }, { status: 201 });
    }

    const orgMatch = ctx.pathname.match(
      /^\/console\/account\/organizations\/([^/]+?)(?:\/(transfer-owner|switch-context))?$/,
    );
    const orgId = orgMatch?.[1] ? decodePathPart(orgMatch[1]) : '';
    const action = String(orgMatch?.[2] || '').trim();

    if (!orgId) {
      return new Response('Not Found', { status: 404 });
    }

    if (ctx.method === 'PATCH' && !action) {
      const request = parseUpdateConsoleAccountOrganizationRequest(await readJson(ctx.request));
      const organization = await account.updateOrganization(
        toAccountContext(auth.claims),
        orgId,
        request,
      );
      await emitConsoleAuditEvent(ctx, auth.claims, {
        category: 'ORG_PROJECT_ENV',
        action: 'organization.update',
        summary: `Updated organization ${organization.id} from account settings`,
        metadata: {
          organizationId: organization.id,
          organizationName: organization.name,
          organizationSlug: organization.slug,
          source: 'account_settings',
        },
      });
      return json({ ok: true, organization }, { status: 200 });
    }

    if (ctx.method === 'POST' && action === 'transfer-owner') {
      const request = parseTransferConsoleAccountOrganizationOwnerRequest(
        await readJson(ctx.request),
      );
      const transfer = await account.transferOrganizationOwner(
        toAccountContext(auth.claims),
        orgId,
        request,
      );
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json({ ok: true, transfer }, { status: 200 });
    }

    if (ctx.method === 'POST' && action === 'switch-context') {
      const sessionOrResponse = requireSessionAdapter(ctx);
      if (sessionOrResponse instanceof Response) return sessionOrResponse;
      const session = sessionOrResponse;
      const nextContext = await account.switchOrganizationContext(
        toAccountContext(auth.claims),
        orgId,
      );
      const parsedSession = await parseConsoleSessionForContextSwitch(
        session,
        headersToRecord(ctx.request.headers),
      );
      if (!parsedSession) {
        return json(
          {
            ok: false,
            code: 'unauthorized',
            message: 'A valid app session is required to switch organization context',
          },
          { status: 401 },
        );
      }
      const jwt = await session.signJwt(
        parsedSession.userId,
        buildConsoleContextSwitchSessionClaims(parsedSession.claims, nextContext),
      );
      return json(
        { ok: true, context: nextContext },
        {
          status: 200,
          headers: { 'Set-Cookie': session.buildSetCookie(jwt) },
        },
      );
    }
  } catch (error: unknown) {
    return sendAccountError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleOnboarding(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleOnboardingPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const onboardingOrResponse = requireOnboardingService(ctx);
  if (onboardingOrResponse instanceof Response) return onboardingOrResponse;
  const onboarding = onboardingOrResponse;

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/onboarding/state') {
      const request = parseGetConsoleOnboardingStateRequest({});
      const state = await onboarding.getOnboardingState(toOnboardingContext(auth.claims), request);
      return json({ ok: true, state }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/onboarding/telemetry') {
      const roleRequired = requireOnboardingTelemetryRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parseGetConsoleOnboardingTelemetryRequest({
        windowMinutes: ctx.url.searchParams.get('windowMinutes') || undefined,
      });
      const telemetry = await onboarding.getOnboardingTelemetry(
        toOnboardingContext(auth.claims),
        request,
      );
      return json({ ok: true, telemetry }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/onboarding/organization') {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseCreateConsoleOnboardingOrganizationRequest(await readJson(ctx.request));
      const result = await onboarding.createOnboardingOrganization(
        toOnboardingContext(auth.claims),
        request,
      );
      if (result.created.owner) {
        await emitConsoleAuditEvent(ctx, auth.claims, {
          category: 'TEAM',
          action: 'member.owner.bootstrap',
          summary: `Bootstrapped owner membership for user ${auth.claims.userId} during onboarding organization step`,
          metadata: {
            onboarding: true,
            onboardingStep: 'organization',
            userId: auth.claims.userId,
          },
        });
      }
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json({ ok: true, result }, { status });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/onboarding/project') {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseCreateConsoleOnboardingProjectRequest(await readJson(ctx.request));
      const result = await onboarding.createOnboardingProject(
        toOnboardingContext(auth.claims),
        request,
      );
      if (result.created.project) {
        await emitConsoleAuditEvent(ctx, auth.claims, {
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
        await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json({ ok: true, result }, { status });
    }
  } catch (error: unknown) {
    return sendOnboardingError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleOpsCockpit(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleOpsCockpitPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  try {
    const telemetryRequest = parseGetConsoleOnboardingTelemetryRequest({
      windowMinutes: ctx.url.searchParams.get('windowMinutes') || undefined,
    });
    const summary = await buildConsoleOpsCockpitSummary({
      claims: auth.claims,
      approvals: ctx.approvals,
      billing: ctx.billing,
      webhooks: ctx.webhooks,
      auditExports: ctx.auditExports,
      enterpriseIsolation: ctx.enterpriseIsolation,
      onboarding: ctx.onboarding,
      canViewOnboardingTelemetry:
        hasConsoleRole(auth.claims, 'admin') || hasConsoleRole(auth.claims, 'ops'),
      telemetryWindowMinutes: telemetryRequest.windowMinutes,
      logger: ctx.logger,
    });
    return json({ ok: true, summary }, { status: 200 });
  } catch (error: unknown) {
    return sendOnboardingError(error);
  }
}

async function handleConsoleObservability(ctx: CloudflareConsoleContext): Promise<Response | null> {
  return await handleConsoleObservabilityRoutes(ctx, {
    json,
    isConsoleObservabilityPath,
    requireConsoleAuth,
    requireObservabilityReadRole,
    requireObservabilityService,
    toAuditContext,
    sendObservabilityError,
  });
}

function isConsoleBillingPath(pathname: string): boolean {
  return pathname.startsWith('/console/billing/');
}

function isConsoleAccountPath(pathname: string): boolean {
  return pathname === '/console/account/profile' || pathname.startsWith('/console/account/organizations');
}

function isConsoleOnboardingPath(pathname: string): boolean {
  return (
    pathname === '/console/onboarding/state' ||
    pathname === '/console/onboarding/telemetry' ||
    pathname === '/console/onboarding/organization' ||
    pathname === '/console/onboarding/project'
  );
}

function isConsoleOpsCockpitPath(pathname: string): boolean {
  return pathname === '/console/ops-cockpit/summary';
}

function isConsoleObservabilityPath(pathname: string): boolean {
  return (
    pathname === '/console/observability/summary' ||
    pathname === '/console/observability/events' ||
    pathname === '/console/observability/timeseries' ||
    pathname === '/console/observability/services'
  );
}

function isConsoleOrgProjectEnvPath(pathname: string): boolean {
  return (
    pathname === '/console/org' ||
    pathname === '/console/projects' ||
    pathname === '/console/environments' ||
    pathname.startsWith('/console/projects/') ||
    pathname.startsWith('/console/environments/')
  );
}

function isConsoleTeamRbacPath(pathname: string): boolean {
  return (
    pathname === '/console/members' ||
    pathname === '/console/members/invite' ||
    pathname.startsWith('/console/members/')
  );
}

function isConsoleApprovalPath(pathname: string): boolean {
  return pathname === '/console/approvals' || pathname.startsWith('/console/approvals/');
}

function isConsoleAuditPath(pathname: string): boolean {
  return pathname === '/console/audit/events' || pathname === '/console/audit/evidence';
}

function isConsoleAuditExportsPath(pathname: string): boolean {
  return pathname === '/console/audit/exports' || pathname.startsWith('/console/audit/exports/');
}

function isConsoleEnterpriseIsolationPath(pathname: string): boolean {
  return pathname === '/console/isolation/status' || pathname === '/console/isolation/trigger';
}

function isConsoleWalletPath(pathname: string): boolean {
  return (
    pathname === '/console/wallets' ||
    pathname === '/console/wallets/search' ||
    pathname.startsWith('/console/wallets/')
  );
}

function isConsolePolicyPath(pathname: string): boolean {
  return pathname === '/console/policies' || pathname.startsWith('/console/policies/');
}

function isConsoleInsightsPath(pathname: string): boolean {
  return (
    pathname === '/console/policy/coverage' ||
    pathname === '/console/gas/readiness' ||
    pathname === '/console/export/governance'
  );
}

function isConsoleApiKeyPath(pathname: string): boolean {
  return pathname.startsWith('/console/api-keys');
}

function isConsoleWebhookPath(pathname: string): boolean {
  return pathname.startsWith('/console/webhooks');
}

function isConsoleGasSponsorshipPath(pathname: string): boolean {
  return (
    pathname === '/console/gas-sponsorship' || pathname.startsWith('/console/gas-sponsorship/')
  );
}

function isConsoleSmartWalletPath(pathname: string): boolean {
  return pathname === '/console/smart-wallets' || pathname.startsWith('/console/smart-wallets/');
}

function isConsoleKeyExportPath(pathname: string): boolean {
  return pathname === '/console/key-exports' || pathname.startsWith('/console/key-exports/');
}

function isConsoleRuntimeSnapshotPath(pathname: string): boolean {
  return (
    pathname === '/console/runtime-snapshots' || pathname.startsWith('/console/runtime-snapshots/')
  );
}

async function handleConsoleGasSponsorship(
  ctx: CloudflareConsoleContext,
): Promise<Response | null> {
  if (!isConsoleGasSponsorshipPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const gasSponsorshipOrResponse = requireGasSponsorshipService(ctx);
  if (gasSponsorshipOrResponse instanceof Response) return gasSponsorshipOrResponse;
  const gasSponsorship = gasSponsorshipOrResponse;
  const configMatch = ctx.pathname.match(/^\/console\/gas-sponsorship\/([^/]+)$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/gas-sponsorship') {
      const request = parseListConsoleGasSponsorshipRequest({
        scopeType: ctx.url.searchParams.get('scopeType') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        policyId: ctx.url.searchParams.get('policyId') || undefined,
        walletSegmentId: ctx.url.searchParams.get('walletSegmentId') || undefined,
      });
      const configs = await gasSponsorship.listConfigs(toBillingContext(auth.claims), request);
      return json({ ok: true, configs }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/gas-sponsorship') {
      const roleRequired = requireConsoleConfigMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parseCreateConsoleGasSponsorshipRequest(await readJson(ctx.request));
      const config = await gasSponsorship.createConfig(toBillingContext(auth.claims), request);
      return json({ ok: true, config }, { status: 201 });
    }

    if (ctx.method === 'PATCH' && configMatch) {
      const roleRequired = requireConsoleConfigMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const configId = decodePathPart(configMatch[1]);
      const request = parseUpdateConsoleGasSponsorshipRequest(await readJson(ctx.request));
      const config = await gasSponsorship.updateConfig(
        toBillingContext(auth.claims),
        configId,
        request,
      );
      if (!config) {
        return json(
          {
            ok: false,
            code: 'gas_sponsorship_not_found',
            message: `Gas sponsorship config ${configId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, config }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendGasSponsorshipError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleSmartWallets(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleSmartWalletPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const smartWalletsOrResponse = requireSmartWalletService(ctx);
  if (smartWalletsOrResponse instanceof Response) return smartWalletsOrResponse;
  const smartWallets = smartWalletsOrResponse;
  const configMatch = ctx.pathname.match(/^\/console\/smart-wallets\/([^/]+)$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/smart-wallets') {
      const request = parseListConsoleSmartWalletRequest({
        scopeType: ctx.url.searchParams.get('scopeType') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        policyId: ctx.url.searchParams.get('policyId') || undefined,
        walletSegmentId: ctx.url.searchParams.get('walletSegmentId') || undefined,
      });
      const configs = await smartWallets.listConfigs(toBillingContext(auth.claims), request);
      return json({ ok: true, configs }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/smart-wallets') {
      const roleRequired = requireConsoleConfigMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parseCreateConsoleSmartWalletRequest(await readJson(ctx.request));
      const config = await smartWallets.createConfig(toBillingContext(auth.claims), request);
      return json({ ok: true, config }, { status: 201 });
    }

    if (ctx.method === 'PATCH' && configMatch) {
      const roleRequired = requireConsoleConfigMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const configId = decodePathPart(configMatch[1]);
      const request = parseUpdateConsoleSmartWalletRequest(await readJson(ctx.request));
      const config = await smartWallets.updateConfig(
        toBillingContext(auth.claims),
        configId,
        request,
      );
      if (!config) {
        return json(
          {
            ok: false,
            code: 'smart_wallet_config_not_found',
            message: `Smart-wallet config ${configId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, config }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendSmartWalletError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleKeyExports(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleKeyExportPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const keyExportsOrResponse = requireKeyExportService(ctx);
  if (keyExportsOrResponse instanceof Response) return keyExportsOrResponse;
  const keyExports = keyExportsOrResponse;
  const approveMatch = ctx.pathname.match(/^\/console\/key-exports\/([^/]+)\/approve$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/key-exports') {
      const request = parseListConsoleKeyExportsRequest({
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        status: ctx.url.searchParams.get('status') || undefined,
      });
      const keyExportRows = await keyExports.listKeyExports(toBillingContext(auth.claims), request);
      return json({ ok: true, exports: keyExportRows }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/key-exports') {
      const request = parseCreateConsoleKeyExportRequest(await readJson(ctx.request));
      const keyExport = await keyExports.createKeyExport(toBillingContext(auth.claims), request);
      return json({ ok: true, keyExport }, { status: 201 });
    }

    if (ctx.method === 'POST' && approveMatch) {
      const roleRequired = requireKeyExportApprovalRole(auth.claims);
      if (roleRequired) return roleRequired;
      const exportId = decodePathPart(approveMatch[1]);
      const rawBody = await readJson(ctx.request);
      const approvalRequired = await requireApprovedOperationApproval(ctx, auth.claims, {
        operationType: 'KEY_EXPORT',
        approvalIdRaw: readApprovalIdFromBody(rawBody),
        resourceType: 'key_export',
        resourceId: exportId,
      });
      if (approvalRequired) return approvalRequired;
      const request = parseApproveConsoleKeyExportRequest(rawBody);
      const keyExport = await keyExports.approveKeyExport(
        toBillingContext(auth.claims),
        exportId,
        request,
      );
      if (!keyExport) {
        return json(
          {
            ok: false,
            code: 'key_export_not_found',
            message: `Key export request ${exportId} was not found`,
          },
          { status: 404 },
        );
      }
      await emitConsoleAuditEvent(ctx, auth.claims, {
        category: 'KEY_EXPORT',
        action: 'key_export.approve',
        summary: `Approved key export request ${keyExport.id}`,
        ...(keyExport.environmentId ? { environmentId: keyExport.environmentId } : {}),
        metadata: {
          keyExportId: keyExport.id,
          status: keyExport.status,
          mode: keyExport.mode,
          approvedByUserId: auth.claims.userId,
        },
      });
      return json({ ok: true, keyExport }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendKeyExportError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleRuntimeSnapshots(
  ctx: CloudflareConsoleContext,
): Promise<Response | null> {
  if (!isConsoleRuntimeSnapshotPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const runtimeSnapshotsOrResponse = requireRuntimeSnapshotService(ctx);
  if (runtimeSnapshotsOrResponse instanceof Response) return runtimeSnapshotsOrResponse;
  const runtimeSnapshots = runtimeSnapshotsOrResponse;

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/runtime-snapshots') {
      const request = parseListConsoleRuntimeSnapshotsRequest({
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
      });
      const snapshots = await runtimeSnapshots.listSnapshots(
        toBillingContext(auth.claims),
        request,
      );
      return json({ ok: true, snapshots }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/runtime-snapshots/latest') {
      const request = parseGetLatestConsoleRuntimeSnapshotRequest({
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
      });
      const snapshot = await runtimeSnapshots.getLatestSnapshot(
        toBillingContext(auth.claims),
        request,
      );
      return json({ ok: true, snapshot }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/runtime-snapshots/publish') {
      const roleRequired = requireConsoleConfigMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parsePublishConsoleRuntimeSnapshotRequest(await readJson(ctx.request));
      const snapshot = await runtimeSnapshots.publishSnapshot(
        toBillingContext(auth.claims),
        request,
      );
      return json({ ok: true, snapshot }, { status: 201 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/runtime-snapshots/publish-current') {
      const roleRequired = requireConsoleConfigMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parsePublishCurrentConsoleRuntimeSnapshotRequest(await readJson(ctx.request));
      const payload = await resolveConsoleRuntimeSnapshotPayload({
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
        roles: auth.claims.roles,
        environmentId: request.environmentId,
        ...(request.projectId ? { projectId: request.projectId } : {}),
        policies: ctx.policies,
        gasSponsorship: ctx.gasSponsorship,
        smartWallets: ctx.smartWallets,
      });
      const snapshot = await runtimeSnapshots.publishSnapshot(toBillingContext(auth.claims), {
        ...request,
        payload,
      });
      return json({ ok: true, snapshot }, { status: 201 });
    }
  } catch (error: unknown) {
    return sendRuntimeSnapshotError(error);
  }

  return new Response('Not Found', { status: 404 });
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
  const apiKeyPurgePathMatch = ctx.pathname.match(/^\/console\/api-keys\/([^/]+)\/purge$/);
  const apiKeyRotatePathMatch = ctx.pathname.match(/^\/console\/api-keys\/([^/]+)\/rotate$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/api-keys') {
      const out = await apiKeys.listApiKeys(apiKeyCtx);
      return json({ ok: true, apiKeys: out }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/api-keys') {
      const roleRequired = requireApiKeyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parseCreateConsoleApiKeyRequest(await readJson(ctx.request));
      const validEnvironment = await requireActiveApiKeyEnvironmentForCreate(
        ctx,
        auth.claims,
        request.environmentId,
      );
      if (validEnvironment) return validEnvironment;
      const created = await apiKeys.createApiKey(apiKeyCtx, request);
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json(
        {
          ok: true,
          apiKey: created.apiKey,
          secret: created.secret,
        },
        { status: 201 },
      );
    }

    if (ctx.method === 'DELETE' && apiKeyPathMatch) {
      const roleRequired = requireApiKeyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const apiKeyId = decodePathPart(apiKeyPathMatch[1]);
      const request = parseRevokeConsoleApiKeyRequest(await readJson(ctx.request));
      const revoked = await apiKeys.revokeApiKey(apiKeyCtx, apiKeyId, request);
      if (!revoked.revoked || !revoked.apiKey) {
        return json(
          {
            ok: false,
            code: 'api_key_not_found',
            message: `API key ${apiKeyId} was not found`,
          },
          { status: 404 },
        );
      }
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json(
        {
          ok: true,
          revoked: true,
          apiKey: revoked.apiKey,
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'DELETE' && apiKeyPurgePathMatch) {
      const roleRequired = requireApiKeyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const apiKeyId = decodePathPart(apiKeyPurgePathMatch[1]);
      const deleted = await apiKeys.deleteApiKey(apiKeyCtx, apiKeyId);
      if (!deleted.deleted || !deleted.apiKey) {
        return json(
          {
            ok: false,
            code: 'api_key_not_found',
            message: `API key ${apiKeyId} was not found`,
          },
          { status: 404 },
        );
      }
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json(
        {
          ok: true,
          deleted: true,
          apiKey: deleted.apiKey,
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'PATCH' && apiKeyPathMatch) {
      const roleRequired = requireApiKeyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const apiKeyId = decodePathPart(apiKeyPathMatch[1]);
      const request = parseUpdateConsoleApiKeyRequest(await readJson(ctx.request));
      const updated = await apiKeys.updateApiKey(apiKeyCtx, apiKeyId, request);
      if (!updated) {
        return json(
          {
            ok: false,
            code: 'api_key_not_found',
            message: `API key ${apiKeyId} was not found`,
          },
          { status: 404 },
        );
      }
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json(
        {
          ok: true,
          apiKey: updated,
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'POST' && apiKeyRotatePathMatch) {
      const roleRequired = requireApiKeyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const apiKeyId = decodePathPart(apiKeyRotatePathMatch[1]);
      const request = parseRotateConsoleApiKeyRequest(await readJson(ctx.request));
      const rotated = await apiKeys.rotateApiKey(apiKeyCtx, apiKeyId, request);
      if (!rotated) {
        return json(
          {
            ok: false,
            code: 'api_key_not_found',
            message: `API key ${apiKeyId} was not found`,
          },
          { status: 404 },
        );
      }
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json(
        {
          ok: true,
          apiKey: rotated.apiKey,
          secret: rotated.secret,
        },
        { status: 200 },
      );
    }
  } catch (error: unknown) {
    return sendApiKeyError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleOrgProjectEnv(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleOrgProjectEnvPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const orgProjectEnvOrResponse = requireOrgProjectEnvService(ctx);
  if (orgProjectEnvOrResponse instanceof Response) return orgProjectEnvOrResponse;
  const orgProjectEnv = orgProjectEnvOrResponse;
  const orgProjectEnvCtx = toOrgProjectEnvContext(auth.claims);
  const projectPatchMatch = ctx.pathname.match(/^\/console\/projects\/([^/]+)$/);
  const projectArchiveMatch = ctx.pathname.match(/^\/console\/projects\/([^/]+)\/archive$/);
  const environmentPatchMatch = ctx.pathname.match(/^\/console\/environments\/([^/]+)$/);
  const environmentArchiveMatch = ctx.pathname.match(/^\/console\/environments\/([^/]+)\/archive$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/org') {
      const org = await orgProjectEnv.getOrganization(orgProjectEnvCtx);
      return json({ ok: true, org }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/projects') {
      const request = parseListConsoleProjectsRequest({
        status: ctx.url.searchParams.get('status') || undefined,
      });
      const projects = await orgProjectEnv.listProjects(orgProjectEnvCtx, request);
      return json({ ok: true, projects }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/environments') {
      const request = parseListConsoleEnvironmentsRequest({
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        status: ctx.url.searchParams.get('status') || undefined,
      });
      const environments = await orgProjectEnv.listEnvironments(orgProjectEnvCtx, request);
      return json({ ok: true, environments }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/projects') {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseCreateConsoleProjectRequest(await readJson(ctx.request));
      const liveEnvironmentsEnabled = ctx.billing
        ? await isBillingReadyForLiveEnvironment(ctx.billing, toBillingContext(auth.claims))
        : false;
      const project = await orgProjectEnv.createProject(orgProjectEnvCtx, {
        ...request,
        liveEnvironmentsEnabled,
      });
      return json({ ok: true, project }, { status: 201 });
    }

    if (ctx.method === 'PATCH' && projectPatchMatch) {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const projectId = decodePathPart(projectPatchMatch[1]);
      const request = parseUpdateConsoleProjectRequest(await readJson(ctx.request));
      const project = await orgProjectEnv.updateProject(orgProjectEnvCtx, projectId, request);
      if (!project) {
        return json(
          {
            ok: false,
            code: 'project_not_found',
            message: `Project ${projectId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, project }, { status: 200 });
    }

    if (ctx.method === 'POST' && projectArchiveMatch) {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const projectId = decodePathPart(projectArchiveMatch[1]);
      const project = await orgProjectEnv.archiveProject(orgProjectEnvCtx, projectId);
      if (!project) {
        return json(
          {
            ok: false,
            code: 'project_not_found',
            message: `Project ${projectId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, project }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/environments') {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseCreateConsoleEnvironmentRequest(await readJson(ctx.request));
      if (request.key !== 'dev') {
        if (!ctx.billing) {
          return sendBillingError(
            new ConsoleBillingError(
              'billing_required_live_environment',
              409,
              LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE,
            ),
          );
        }
        await ensureBillingReadyForLiveEnvironment(ctx.billing, toBillingContext(auth.claims));
      }
      const environment = await orgProjectEnv.createEnvironment(orgProjectEnvCtx, request);
      return json({ ok: true, environment }, { status: 201 });
    }

    if (ctx.method === 'PATCH' && environmentPatchMatch) {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const environmentId = decodePathPart(environmentPatchMatch[1]);
      const request = parseUpdateConsoleEnvironmentRequest(await readJson(ctx.request));
      const environment = await orgProjectEnv.updateEnvironment(
        orgProjectEnvCtx,
        environmentId,
        request,
      );
      if (!environment) {
        return json(
          {
            ok: false,
            code: 'environment_not_found',
            message: `Environment ${environmentId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, environment }, { status: 200 });
    }

    if (ctx.method === 'POST' && environmentArchiveMatch) {
      const forbidden = requireOrgProjectEnvMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const environmentId = decodePathPart(environmentArchiveMatch[1]);
      const environment = await orgProjectEnv.archiveEnvironment(orgProjectEnvCtx, environmentId);
      if (!environment) {
        return json(
          {
            ok: false,
            code: 'environment_not_found',
            message: `Environment ${environmentId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, environment }, { status: 200 });
    }
  } catch (error: unknown) {
    if (isConsoleBillingError(error)) return sendBillingError(error);
    return sendOrgProjectEnvError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleTeamRbac(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleTeamRbacPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const teamRbacOrResponse = requireTeamRbacService(ctx);
  if (teamRbacOrResponse instanceof Response) return teamRbacOrResponse;
  const teamRbac = teamRbacOrResponse;
  const teamRbacCtx = toTeamRbacContext(auth.claims);
  const memberRolesPathMatch = ctx.pathname.match(/^\/console\/members\/([^/]+)\/roles$/);
  const memberDeletePathMatch = ctx.pathname.match(/^\/console\/members\/([^/]+)$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/members') {
      const request = parseListConsoleTeamMembersRequest({
        status: ctx.url.searchParams.get('status') || undefined,
      });
      const members = await teamRbac.listMembers(teamRbacCtx, request);
      return json({ ok: true, members }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/members/invite') {
      const forbidden = requireTeamRbacMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseInviteConsoleTeamMemberRequest(await readJson(ctx.request));
      const member = await teamRbac.inviteMember(teamRbacCtx, request);
      return json({ ok: true, member }, { status: 201 });
    }

    if (ctx.method === 'PATCH' && memberRolesPathMatch) {
      const forbidden = requireTeamRbacMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const memberId = decodePathPart(memberRolesPathMatch[1]);
      const request = parseUpdateConsoleTeamMemberRolesRequest(await readJson(ctx.request));
      const member = await teamRbac.updateMemberRoles(teamRbacCtx, memberId, request);
      if (!member) {
        return json(
          {
            ok: false,
            code: 'member_not_found',
            message: `Member ${memberId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, member }, { status: 200 });
    }

    if (ctx.method === 'DELETE' && memberDeletePathMatch) {
      const forbidden = requireTeamRbacMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const memberId = decodePathPart(memberDeletePathMatch[1]);
      const removed = await teamRbac.removeMember(teamRbacCtx, memberId);
      if (!removed.removed || !removed.member) {
        return json(
          {
            ok: false,
            code: 'member_not_found',
            message: `Member ${memberId} was not found`,
          },
          { status: 404 },
        );
      }
      return json(
        {
          ok: true,
          removed: true,
          member: removed.member,
        },
        { status: 200 },
      );
    }
  } catch (error: unknown) {
    return sendTeamRbacError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleApprovals(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleApprovalPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const approvalsOrResponse = requireApprovalService(ctx);
  if (approvalsOrResponse instanceof Response) return approvalsOrResponse;
  const approvals = approvalsOrResponse;
  const approvalCtx = toApprovalContext(auth.claims);
  const approvalPathMatch = ctx.pathname.match(/^\/console\/approvals\/([^/]+)$/);
  const approvalApprovePathMatch = ctx.pathname.match(/^\/console\/approvals\/([^/]+)\/approve$/);
  const approvalRejectPathMatch = ctx.pathname.match(/^\/console\/approvals\/([^/]+)\/reject$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/approvals') {
      const request = parseListConsoleApprovalsRequest({
        status: ctx.url.searchParams.get('status') || undefined,
        operationType: ctx.url.searchParams.get('operationType') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
      });
      const rows = await approvals.listApprovalRequests(approvalCtx, request);
      return json({ ok: true, approvals: rows }, { status: 200 });
    }

    if (ctx.method === 'GET' && approvalPathMatch) {
      const approvalId = decodePathPart(approvalPathMatch[1]);
      const row = await approvals.getApprovalRequest(approvalCtx, approvalId);
      if (!row) {
        return json(
          {
            ok: false,
            code: 'approval_not_found',
            message: `Approval request ${approvalId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, approval: row }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/approvals') {
      const forbidden = requireApprovalMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseCreateConsoleApprovalRequest(await readJson(ctx.request));
      const row = await approvals.createApprovalRequest(approvalCtx, request);
      await emitApprovalWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
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
        },
      });
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
        },
      });
      return json({ ok: true, approval: row }, { status: 201 });
    }

    if (ctx.method === 'POST' && approvalApprovePathMatch) {
      const forbidden = requireApprovalMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const approvalId = decodePathPart(approvalApprovePathMatch[1]);
      const request = parseApproveConsoleApprovalRequest(await readJson(ctx.request));
      const row = await approvals.approveApprovalRequest(approvalCtx, approvalId, request);
      if (!row) {
        return json(
          {
            ok: false,
            code: 'approval_not_found',
            message: `Approval request ${approvalId} was not found`,
          },
          { status: 404 },
        );
      }
      await emitApprovalWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
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
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
        },
      });
      return json({ ok: true, approval: row }, { status: 200 });
    }

    if (ctx.method === 'POST' && approvalRejectPathMatch) {
      const forbidden = requireApprovalMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const approvalId = decodePathPart(approvalRejectPathMatch[1]);
      const request = parseRejectConsoleApprovalRequest(await readJson(ctx.request));
      const row = await approvals.rejectApprovalRequest(approvalCtx, approvalId, request);
      if (!row) {
        return json(
          {
            ok: false,
            code: 'approval_not_found',
            message: `Approval request ${approvalId} was not found`,
          },
          { status: 404 },
        );
      }
      await emitApprovalWebhookEvent(ctx, {
        orgId: auth.claims.orgId,
        actorUserId: auth.claims.userId,
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
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
        },
      });
      return json({ ok: true, approval: row }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendApprovalError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleAudit(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleAuditPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const auditOrResponse = requireAuditService(ctx);
  if (auditOrResponse instanceof Response) return auditOrResponse;
  const audit = auditOrResponse;

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/audit/events') {
      const request = parseListConsoleAuditEventsRequest({
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        category: ctx.url.searchParams.get('category') || undefined,
        actorUserId: ctx.url.searchParams.get('actorUserId') || undefined,
        outcome: ctx.url.searchParams.get('outcome') || undefined,
        q: ctx.url.searchParams.get('q') || undefined,
        from: ctx.url.searchParams.get('from') || undefined,
        to: ctx.url.searchParams.get('to') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
      });
      const events = await audit.listEvents(toAuditContext(auth.claims), request);
      return json({ ok: true, events }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/audit/evidence') {
      const request = parseListConsoleAuditEvidenceRequest({
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
        domain: ctx.url.searchParams.get('domain') || undefined,
        from: ctx.url.searchParams.get('from') || undefined,
        to: ctx.url.searchParams.get('to') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
      });
      const evidence = await audit.listEvidence(toAuditContext(auth.claims), request);
      return json({ ok: true, evidence }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendAuditError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleAuditExports(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleAuditExportsPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const auditExportsOrResponse = requireAuditExportsService(ctx);
  if (auditExportsOrResponse instanceof Response) return auditExportsOrResponse;
  const auditExports = auditExportsOrResponse;

  const exportMatch = ctx.pathname.match(/^\/console\/audit\/exports\/([^/]+)$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/audit/exports') {
      const request = parseListConsoleAuditExportsRequest({
        status: ctx.url.searchParams.get('status') || undefined,
        domain: ctx.url.searchParams.get('domain') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
      });
      const exports = await auditExports.listExports(toAuditContext(auth.claims), request);
      return json({ ok: true, exports }, { status: 200 });
    }

    if (ctx.method === 'GET' && exportMatch) {
      const exportId = decodePathPart(exportMatch[1]);
      const auditExport = await auditExports.getExport(toAuditContext(auth.claims), exportId);
      if (!auditExport) {
        return json(
          {
            ok: false,
            code: 'audit_export_not_found',
            message: `Audit export ${exportId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, export: auditExport }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/audit/exports') {
      const forbidden = requireEnterpriseIsolationMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseCreateConsoleAuditExportRequest(await readJson(ctx.request));
      const auditExport = await auditExports.createExport(toAuditContext(auth.claims), request);
      return json({ ok: true, export: auditExport }, { status: 201 });
    }
  } catch (error: unknown) {
    return sendAuditExportsError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleEnterpriseIsolation(
  ctx: CloudflareConsoleContext,
): Promise<Response | null> {
  if (!isConsoleEnterpriseIsolationPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const enterpriseIsolationOrResponse = requireEnterpriseIsolationService(ctx);
  if (enterpriseIsolationOrResponse instanceof Response) return enterpriseIsolationOrResponse;
  const enterpriseIsolation = enterpriseIsolationOrResponse;

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/isolation/status') {
      const request = parseGetConsoleEnterpriseIsolationRequest({
        scope: ctx.url.searchParams.get('scope') || undefined,
        projectId: ctx.url.searchParams.get('projectId') || undefined,
        environmentId: ctx.url.searchParams.get('environmentId') || undefined,
      });
      const isolation = await enterpriseIsolation.getIsolationState(
        toAuditContext(auth.claims),
        request,
      );
      return json({ ok: true, isolation }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/isolation/trigger') {
      const forbidden = requireEnterpriseIsolationMutationRole(auth.claims);
      if (forbidden) return forbidden;
      const request = parseTriggerConsoleEnterpriseIsolationRequest(await readJson(ctx.request));
      const isolation = await enterpriseIsolation.triggerIsolation(
        toAuditContext(auth.claims),
        request,
      );
      await emitConsoleAuditEvent(ctx, auth.claims, {
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
      return json({ ok: true, isolation }, { status: 202 });
    }
  } catch (error: unknown) {
    return sendEnterpriseIsolationError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleWallets(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleWalletPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const walletsOrResponse = requireWalletService(ctx);
  if (walletsOrResponse instanceof Response) return walletsOrResponse;
  const wallets = walletsOrResponse;
  const walletCtx = toWalletContext(auth.claims);
  const walletMatch = ctx.pathname.match(/^\/console\/wallets\/([^/]+)$/);

  const query = {
    limit: ctx.url.searchParams.get('limit') || undefined,
    cursor: ctx.url.searchParams.get('cursor') || undefined,
    projectId: ctx.url.searchParams.get('projectId') || undefined,
    environmentId: ctx.url.searchParams.get('environmentId') || undefined,
    chain: ctx.url.searchParams.get('chain') || undefined,
    walletType: ctx.url.searchParams.get('walletType') || undefined,
    status: ctx.url.searchParams.get('status') || undefined,
    policyId: ctx.url.searchParams.get('policyId') || undefined,
    userId: ctx.url.searchParams.get('userId') || undefined,
    externalRefId: ctx.url.searchParams.get('externalRefId') || undefined,
    sortBy: ctx.url.searchParams.get('sortBy') || undefined,
    sortOrder: ctx.url.searchParams.get('sortOrder') || undefined,
  };

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/wallets') {
      const request = parseListConsoleWalletsRequest(query);
      const page = await wallets.listWallets(walletCtx, request);
      return json(
        {
          ok: true,
          wallets: page.items,
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/wallets/search') {
      const request = parseSearchConsoleWalletsRequest({
        ...query,
        q: ctx.url.searchParams.get('q') || undefined,
      });
      const page = await wallets.searchWallets(walletCtx, request);
      return json(
        {
          ok: true,
          wallets: page.items,
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'GET' && walletMatch) {
      const walletId = decodePathPart(walletMatch[1]);
      const wallet = await wallets.getWallet(walletCtx, walletId);
      if (!wallet) {
        return json(
          {
            ok: false,
            code: 'wallet_not_found',
            message: `Wallet ${walletId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, wallet }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendWalletError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsolePolicies(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsolePolicyPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const policiesOrResponse = requirePolicyService(ctx);
  if (policiesOrResponse instanceof Response) return policiesOrResponse;
  const policies = policiesOrResponse;
  const policyCtx = toBillingContext(auth.claims);

  const assignmentDeleteMatch = ctx.pathname.match(/^\/console\/policies\/assignments\/([^/]+)$/);
  const policyPatchMatch = ctx.pathname.match(/^\/console\/policies\/([^/]+)$/);
  const policyDeleteMatch = ctx.pathname.match(/^\/console\/policies\/([^/]+)$/);
  const policyPublishMatch = ctx.pathname.match(/^\/console\/policies\/([^/]+)\/publish$/);
  const policySimulateMatch = ctx.pathname.match(/^\/console\/policies\/([^/]+)\/simulate$/);

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/policies') {
      const out = await policies.listPolicies(policyCtx);
      return json({ ok: true, policies: out }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/policies/assignments') {
      const request = parseListConsolePolicyAssignmentsRequest({
        scopeType: ctx.url.searchParams.get('scopeType') || undefined,
        scopeId: ctx.url.searchParams.get('scopeId') || undefined,
      });
      const assignments = await policies.listAssignments(policyCtx, request);
      return json({ ok: true, assignments }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/policies') {
      const roleRequired = requirePolicyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parseCreateConsolePolicyRequest(await readJson(ctx.request));
      const policy = await policies.createPolicy(policyCtx, request);
      return json({ ok: true, policy }, { status: 201 });
    }

    if (ctx.method === 'PUT' && ctx.pathname === '/console/policies/assignments') {
      const roleRequired = requirePolicyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const request = parseUpsertConsolePolicyAssignmentRequest(await readJson(ctx.request));
      const assignment = await policies.upsertAssignment(policyCtx, request);
      return json({ ok: true, assignment }, { status: 200 });
    }

    if (ctx.method === 'DELETE' && assignmentDeleteMatch) {
      const roleRequired = requirePolicyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const assignmentId = decodePathPart(assignmentDeleteMatch[1]);
      const out = await policies.deleteAssignment(policyCtx, assignmentId);
      if (!out.removed || !out.assignment) {
        return json(
          {
            ok: false,
            code: 'assignment_not_found',
            message: `Assignment ${assignmentId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, removed: true, assignment: out.assignment }, { status: 200 });
    }

    if (ctx.method === 'PATCH' && policyPatchMatch) {
      const roleRequired = requirePolicyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const policyId = decodePathPart(policyPatchMatch[1]);
      const request = parseUpdateConsolePolicyRequest(await readJson(ctx.request));
      const policy = await policies.updatePolicy(policyCtx, policyId, request);
      if (!policy) {
        return json(
          {
            ok: false,
            code: 'policy_not_found',
            message: `Policy ${policyId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, policy }, { status: 200 });
    }

    if (ctx.method === 'DELETE' && policyDeleteMatch) {
      const roleRequired = requirePolicyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const policyId = decodePathPart(policyDeleteMatch[1]);
      const result = await policies.deletePolicy(policyCtx, policyId);
      if (!result.removed || !result.policy) {
        return json(
          {
            ok: false,
            code: 'policy_not_found',
            message: `Policy ${policyId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, removed: true, policy: result.policy }, { status: 200 });
    }

    if (ctx.method === 'POST' && policyPublishMatch) {
      const roleRequired = requirePolicyMutationRole(auth.claims);
      if (roleRequired) return roleRequired;
      const policyId = decodePathPart(policyPublishMatch[1]);
      const rawBody = await readJson(ctx.request);
      const approvalIdForFailure = readApprovalIdFromBody(rawBody);
      const approvalRequired = await requireApprovedOperationApproval(ctx, auth.claims, {
        operationType: 'POLICY_PUBLISH',
        approvalIdRaw: approvalIdForFailure,
        resourceType: 'policy',
        resourceId: policyId,
      });
      if (approvalRequired) return approvalRequired;
      try {
        const result = await policies.publishPolicy(policyCtx, policyId);
        if (!result) {
          return json(
            {
              ok: false,
              code: 'policy_not_found',
              message: `Policy ${policyId} was not found`,
            },
            { status: 404 },
          );
        }
        await emitConsoleAuditEvent(ctx, auth.claims, {
          category: 'POLICY',
          action: 'policy.publish',
          summary: `Published policy ${policyId}`,
          metadata: {
            policyId,
            version: result.policy.version,
            status: result.policy.status,
          },
        });
        return json({ ok: true, result }, { status: 200 });
      } catch (error: unknown) {
        await emitApprovalFailureObservabilityEvent(ctx, auth.claims, {
          approvalId: approvalIdForFailure,
          operationType: 'POLICY_PUBLISH',
          resourceType: 'policy',
          resourceId: policyId,
          error,
        });
        throw error;
      }
    }

    if (ctx.method === 'POST' && policySimulateMatch) {
      const policyId = decodePathPart(policySimulateMatch[1]);
      const request = parseSimulateConsolePolicyRequest(await readJson(ctx.request));
      const simulation = await policies.simulatePolicy(policyCtx, policyId, request);
      if (!simulation) {
        return json(
          {
            ok: false,
            code: 'policy_not_found',
            message: `Policy ${policyId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, simulation }, { status: 200 });
    }
  } catch (error: unknown) {
    return sendPolicyError(error);
  }

  return new Response('Not Found', { status: 404 });
}

async function handleConsoleInsights(ctx: CloudflareConsoleContext): Promise<Response | null> {
  if (!isConsoleInsightsPath(ctx.pathname)) return null;

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  try {
    if (ctx.method === 'GET' && ctx.pathname === '/console/policy/coverage') {
      const walletsOrResponse = requireWalletService(ctx);
      if (walletsOrResponse instanceof Response) return walletsOrResponse;
      const scope = resolveConsoleInsightsScope({
        projectIdRaw: ctx.url.searchParams.get('projectId') || undefined,
        environmentIdRaw: ctx.url.searchParams.get('environmentId') || undefined,
        claimsProjectId: auth.claims.projectId,
        claimsEnvironmentId: auth.claims.environmentId,
      });
      const coverage = await buildConsolePolicyCoverageView({
        wallets: walletsOrResponse,
        walletCtx: toWalletContext(auth.claims),
        scope,
        ...(ctx.policies
          ? {
              resolvePolicyIds: async (walletRows) =>
                await ctx.policies!.resolvePoliciesForWallets(
                  toBillingContext(auth.claims),
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
      return json({ ok: true, coverage }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/gas/readiness') {
      const walletsOrResponse = requireWalletService(ctx);
      if (walletsOrResponse instanceof Response) return walletsOrResponse;
      const scope = resolveConsoleInsightsScope({
        projectIdRaw: ctx.url.searchParams.get('projectId') || undefined,
        environmentIdRaw: ctx.url.searchParams.get('environmentId') || undefined,
        claimsProjectId: auth.claims.projectId,
        claimsEnvironmentId: auth.claims.environmentId,
      });
      const readiness = await buildConsoleGasReadinessView({
        wallets: walletsOrResponse,
        walletCtx: toWalletContext(auth.claims),
        scope,
        recentWindowDays: 7,
      });
      return json({ ok: true, readiness }, { status: 200 });
    }

    if (ctx.method === 'GET' && ctx.pathname === '/console/export/governance') {
      const apiKeysOrResponse = requireApiKeyService(ctx);
      if (apiKeysOrResponse instanceof Response) return apiKeysOrResponse;
      const environmentIdRaw = String(ctx.url.searchParams.get('environmentId') || '').trim();
      const environmentIdFilter = environmentIdRaw || auth.claims.environmentId || undefined;
      const governance = await buildConsoleExportGovernanceView({
        apiKeys: apiKeysOrResponse,
        apiKeyCtx: toBillingContext(auth.claims),
        environmentIdFilter,
      });
      return json({ ok: true, governance }, { status: 200 });
    }
  } catch (error: unknown) {
    if (ctx.pathname.startsWith('/console/export/')) return sendApiKeyError(error);
    return sendWalletError(error);
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
        return json(
          {
            ok: false,
            code: 'webhook_not_found',
            message: `Webhook endpoint ${endpointId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, endpoint }, { status: 200 });
    }

    if (ctx.method === 'DELETE' && endpointMatch) {
      const endpointId = decodePathPart(endpointMatch[1]);
      const out = await webhooks.deleteEndpoint(webhookCtx, endpointId);
      if (!out.removed) {
        return json(
          {
            ok: false,
            code: 'webhook_not_found',
            message: `Webhook endpoint ${endpointId} was not found`,
          },
          { status: 404 },
        );
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
      return json(
        {
          ok: true,
          deliveries: page.items,
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'GET' && attemptsMatch) {
      const endpointId = decodePathPart(attemptsMatch[1]);
      const request = parseListConsoleWebhookAttemptsRequest({
        deliveryId: ctx.url.searchParams.get('deliveryId') || undefined,
        limit: ctx.url.searchParams.get('limit') || undefined,
        cursor: ctx.url.searchParams.get('cursor') || undefined,
      });
      const page = await webhooks.listAttempts(webhookCtx, endpointId, request);
      return json(
        {
          ok: true,
          attempts: page.items,
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        },
        { status: 200 },
      );
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
      return json(
        {
          ok: true,
          deadLetters: page.items,
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'POST' && replayMatch) {
      const endpointId = decodePathPart(replayMatch[1]);
      const request = parseReplayConsoleWebhookDeliveryRequest(await readJson(ctx.request));
      const replay = await webhooks.replayDelivery(webhookCtx, endpointId, request);
      if (!replay.replayed) {
        if (replay.reason === 'endpoint_not_found') {
          return json(
            {
              ok: false,
              code: 'webhook_not_found',
              message: `Webhook endpoint ${endpointId} was not found`,
            },
            { status: 404 },
          );
        }
        if (replay.reason === 'delivery_not_found') {
          return json(
            {
              ok: false,
              code: 'delivery_not_found',
              message: `Webhook delivery ${request.deliveryId} was not found`,
            },
            { status: 404 },
          );
        }
        return json(
          {
            ok: false,
            code: 'no_replayable_delivery',
            message: 'No replayable delivery exists for this endpoint',
          },
          { status: 409 },
        );
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

  if (
    ctx.pathname === '/console/billing/subscription' ||
    ctx.pathname === '/console/billing/subscription/cancel' ||
    ctx.pathname === '/console/billing/subscription/resume'
  ) {
    return new Response('Not Found', { status: 404 });
  }

  if (
    (ctx.method === 'POST' && ctx.pathname === '/console/billing/stripe/payment-intent') ||
    (ctx.method === 'GET' && ctx.pathname === '/console/billing/stablecoins/assets') ||
    (ctx.method === 'POST' && ctx.pathname === '/console/billing/stablecoins/quotes') ||
    (ctx.method === 'POST' && ctx.pathname === '/console/billing/stablecoins/payment-intents') ||
    /^\/console\/billing\/stripe\/payment-intents\/[^/]+\/reconcile$/.test(ctx.pathname) ||
    /^\/console\/billing\/stablecoins\/payment-intents\/[^/]+$/.test(ctx.pathname) ||
    /^\/console\/billing\/stablecoins\/payment-intents\/[^/]+\/cancel$/.test(ctx.pathname) ||
    /^\/console\/billing\/stablecoins\/payment-intents\/[^/]+\/reconcile$/.test(ctx.pathname)
  ) {
    return new Response('Not Found', { status: 404 });
  }

  if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stripe/webhook') {
    const secretRequired = requireStripeWebhookSecret(ctx);
    if (secretRequired) return secretRequired;
    const billingOrResponse = requireBillingService(ctx);
    if (billingOrResponse instanceof Response) return billingOrResponse;
    try {
      const request = parseStripeWebhookEventRequest(await readJson(ctx.request));
      const result = await billingOrResponse.processStripeWebhookEvent(request);
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
      }
      return json({ ok: true, ...result }, { status: 200 });
    } catch (error: unknown) {
      return sendBillingError(error);
    }
  }

  const auth = await requireConsoleAuth(ctx);
  if (!auth.ok) return auth.response;

  const invoiceMatch = ctx.pathname.match(/^\/console\/billing\/invoices\/([^/]+)$/);
  const invoicePdfMatch = ctx.pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/pdf$/);
  const invoiceActivityMatch = ctx.pathname.match(
    /^\/console\/billing\/invoices\/([^/]+)\/activity$/,
  );
  const invoiceLineItemsMatch = ctx.pathname.match(
    /^\/console\/billing\/invoices\/([^/]+)\/line-items$/,
  );
  const paymentMethodMatch = ctx.pathname.match(/^\/console\/billing\/payment-methods\/([^/]+)$/);
  const paymentMethodDefaultMatch = ctx.pathname.match(
    /^\/console\/billing\/payment-methods\/([^/]+)\/default$/,
  );
  let billingFailureEvent: {
    operation: 'INVOICE_FINALIZATION';
    invoiceId?: string;
  } | null = null;

  try {
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
      billingFailureEvent = {
        operation: 'INVOICE_FINALIZATION',
        invoiceId: `monthly:${request.periodMonthUtc}`,
      };
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
      const request = parseBillingInvoiceListRequest(
        Object.fromEntries(ctx.url.searchParams.entries()),
      );
      const page = await billing.listInvoicesPage(billingCtx, request);
      return json(
        {
          ok: true,
          invoices: page.invoices,
          nextCursor: page.nextCursor,
          totalCount: page.totalCount,
          summary: page.summary,
        },
        { status: 200 },
      );
    }

    if (ctx.method === 'GET' && invoiceMatch) {
      const invoiceId = decodePathPart(invoiceMatch[1]);
      const invoice = await billing.getInvoice(billingCtx, invoiceId);
      if (!invoice) {
        return json(
          {
            ok: false,
            code: 'invoice_not_found',
            message: `Invoice ${invoiceId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, invoice }, { status: 200 });
    }

    if (ctx.method === 'GET' && invoicePdfMatch) {
      const invoiceId = decodePathPart(invoicePdfMatch[1]);
      const invoice = await billing.getInvoice(billingCtx, invoiceId);
      if (!invoice) {
        return json(
          {
            ok: false,
            code: 'invoice_not_found',
            message: `Invoice ${invoiceId} was not found`,
          },
          { status: 404 },
        );
      }
      const lineItems = await billing.listInvoiceLineItems(billingCtx, invoiceId);
      await emitConsoleAuditEvent(ctx, auth.claims, {
        category: 'BILLING',
        action: 'billing.invoice.pdf_export',
        summary: `Exported billing invoice PDF for ${invoice.id}`,
        metadata: {
          invoiceId: invoice.id,
          invoiceStatus: invoice.status,
          periodMonthUtc: invoice.periodMonthUtc,
          exportPolicy: 'ALL_INVOICE_STATES',
        },
      });
      const headers = new Headers({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${buildConsoleBillingInvoicePdfFilename(invoice)}"`,
      });
      return new Response(
        buildConsoleBillingInvoicePdf({
          orgId: auth.claims.orgId,
          invoice,
          lineItems,
        }),
        {
          status: 200,
          headers,
        },
      );
    }

    if (ctx.method === 'GET' && invoiceActivityMatch) {
      const invoiceId = decodePathPart(invoiceActivityMatch[1]);
      const activity = await billing.getInvoiceActivity(billingCtx, invoiceId);
      if (!activity) {
        return json(
          {
            ok: false,
            code: 'invoice_not_found',
            message: `Invoice ${invoiceId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, activity }, { status: 200 });
    }

    if (ctx.method === 'GET' && invoiceLineItemsMatch) {
      const invoiceId = decodePathPart(invoiceLineItemsMatch[1]);
      const invoice = await billing.getInvoice(billingCtx, invoiceId);
      if (!invoice) {
        return json(
          {
            ok: false,
            code: 'invoice_not_found',
            message: `Invoice ${invoiceId} was not found`,
          },
          { status: 404 },
        );
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
        return json(
          {
            ok: false,
            code: 'payment_method_not_found',
            message: `Payment method ${paymentMethodId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, removed: true }, { status: 200 });
    }

    if (ctx.method === 'POST' && paymentMethodDefaultMatch) {
      const adminRequired = requireAdminRoleForCardActions(auth.claims);
      if (adminRequired) return adminRequired;
      const paymentMethodId = decodePathPart(paymentMethodDefaultMatch[1]);
      const paymentMethod = await billing.setDefaultCardPaymentMethod(billingCtx, paymentMethodId);
      if (!paymentMethod) {
        return json(
          {
            ok: false,
            code: 'payment_method_not_found',
            message: `Payment method ${paymentMethodId} was not found`,
          },
          { status: 404 },
        );
      }
      return json({ ok: true, paymentMethod }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stripe/setup-intent') {
      const request = parseStripeSetupIntentRequest(await readJson(ctx.request));
      const setupIntent = await billing.createStripeSetupIntent(billingCtx, request);
      return json({ ok: true, setupIntent }, { status: 200 });
    }

    if (ctx.method === 'POST' && ctx.pathname === '/console/billing/stripe/checkout-session') {
      const request = parseStripeCheckoutSessionRequest(await readJson(ctx.request));
      const checkoutSession = await billing.createStripeCheckoutSession(billingCtx, request);
      return json({ ok: true, checkoutSession }, { status: 201 });
    }

    if (
      ctx.method === 'POST' &&
      ctx.pathname === '/console/billing/stripe/customer-portal-session'
    ) {
      const request = parseStripeCustomerPortalSessionRequest(await readJson(ctx.request));
      const portalSession = await billing.createStripeCustomerPortalSession(billingCtx, request);
      return json({ ok: true, portalSession }, { status: 201 });
    }
  } catch (error: unknown) {
    if (billingFailureEvent) {
      await emitBillingFailureObservabilityEvent(ctx, auth.claims, {
        operation: billingFailureEvent.operation,
        ...(billingFailureEvent.invoiceId ? { invoiceId: billingFailureEvent.invoiceId } : {}),
        error,
      });
    }
    return sendBillingError(error);
  }

  return new Response('Not Found', { status: 404 });
}

export function createCloudflareConsoleRouter(opts: ConsoleRouterOptions = {}): FetchHandler {
  const notFound = () => new Response('Not Found', { status: 404 });
  const logger = coerceRouterLogger(opts.logger);
  const billing = opts.billing === undefined ? null : opts.billing;
  const orgProjectEnv = opts.orgProjectEnv === undefined ? null : opts.orgProjectEnv;
  const wallets = opts.wallets === undefined ? null : opts.wallets;
  const policies = opts.policies === undefined ? null : opts.policies;
  const apiKeys = opts.apiKeys === undefined ? null : opts.apiKeys;
  const webhooks = opts.webhooks === undefined ? null : opts.webhooks;
  const gasSponsorship = opts.gasSponsorship === undefined ? null : opts.gasSponsorship;
  const smartWallets = opts.smartWallets === undefined ? null : opts.smartWallets;
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

  const handlers: Array<(ctx: CloudflareConsoleContext) => Promise<Response | null>> = [
    handleConsoleHealth,
    handleConsoleReady,
    handleConsoleSession,
    handleConsoleAccount,
    handleConsoleOnboarding,
    handleConsoleOpsCockpit,
    handleConsoleObservability,
    handleConsoleOrgProjectEnv,
    handleConsoleTeamRbac,
    handleConsoleApprovals,
    handleConsoleAudit,
    handleConsoleAuditExports,
    handleConsoleEnterpriseIsolation,
    handleConsoleWallets,
    handleConsolePolicies,
    handleConsoleInsights,
    handleConsoleGasSponsorship,
    handleConsoleSmartWallets,
    handleConsoleKeyExports,
    handleConsoleRuntimeSnapshots,
    handleConsoleApiKeys,
    handleConsoleWebhooks,
    handleConsoleBilling,
  ];

  return async function handler(
    request: Request,
    env?: CfEnv,
    cfCtx?: CfExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method.toUpperCase();
    const startedAtMs = Date.now();

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
      orgProjectEnv,
      wallets,
      policies,
      apiKeys,
      webhooks,
      gasSponsorship,
      smartWallets,
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

    try {
      for (const fn of handlers) {
        const res = await fn(ctx);
        if (res) {
          withConsoleCors(res.headers, opts, request);
          void emitRouterTimingObservabilityEvent(ctx, startedAtMs, res.status);
          return res;
        }
      }
      const res = notFound();
      withConsoleCors(res.headers, opts, request);
      void emitRouterTimingObservabilityEvent(ctx, startedAtMs, res.status);
      return res;
    } catch (e: unknown) {
      const res = json(
        { code: 'internal', message: e instanceof Error ? e.message : String(e) },
        { status: 500 },
      );
      withConsoleCors(res.headers, opts, request);
      void emitRouterTimingObservabilityEvent(ctx, startedAtMs, res.status);
      return res;
    }
  };
}

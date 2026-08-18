import { ConsoleBillingError } from '@seams-internal/console-server/billing/errors';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing/service';
import type {
  BillingAccountActivityRequest,
  BillingAccountActivityResult,
  BillingManualAdjustmentRequest,
  BillingOverview,
  BillingRefund,
  BillingRefundReconcileRequest,
  BillingRefundRequest,
} from '@seams-internal/console-server/billing/types';
import {
  parseBillingAccountActivityRequest,
  parseBillingManualAdjustmentRequest,
  parseBillingRefundReconcileRequest,
  parseBillingRefundRequest,
} from '@seams-internal/console-server/billing/requests';
import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv/service';
import type {
  ConsoleOrganization,
  ConsoleProject,
} from '@seams-internal/console-server/orgProjectEnv/types';
import {
  readRequiredStringField,
  readOptionalQueryStringField,
  requireBodyObject,
  requireQueryObject,
} from '@seams-internal/console-server/shared/requestParse';
import type { ConsoleAuthClaims } from '@seams-internal/console-server/router/consoleAuth';

function createParseError(code: string, status: number, message: string): ConsoleBillingError {
  return new ConsoleBillingError(code, status, message);
}

function toPlatformLookupReadContext(
  claims: ConsoleAuthClaims,
  orgId: string,
): {
  orgId: string;
  actorUserId: string;
  projectId?: string;
  environmentId?: string;
} {
  return {
    orgId,
    actorUserId: claims.userId,
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
  };
}

function toPlatformBillingContext(
  claims: ConsoleAuthClaims,
  orgId: string,
): {
  orgId: string;
  actorUserId: string;
} {
  return {
    orgId,
    actorUserId: claims.userId,
  };
}

export interface PlatformBillingLookupRequest {
  orgId?: string;
  projectId?: string;
  activity: BillingAccountActivityRequest;
}

export interface PlatformBillingOrganizationSearchRequest {
  query: string;
  limit?: number;
}

export interface PlatformBillingLookupResult {
  resolvedBy: 'org_id' | 'project_id';
  organization: ConsoleOrganization;
  project: ConsoleProject | null;
  overview: BillingOverview;
  activity: BillingAccountActivityResult;
  refunds: BillingRefund[];
}

const DEFAULT_PLATFORM_BILLING_ORGANIZATION_SEARCH_LIMIT = 10;
const MAX_PLATFORM_BILLING_ORGANIZATION_SEARCH_LIMIT = 20;

function normalizePlatformBillingSearchLimit(limit: unknown): number {
  const numeric = Number(limit || 0);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return DEFAULT_PLATFORM_BILLING_ORGANIZATION_SEARCH_LIMIT;
  }
  return Math.max(1, Math.min(MAX_PLATFORM_BILLING_ORGANIZATION_SEARCH_LIMIT, Math.floor(numeric)));
}

export interface PlatformBillingManualAdjustmentRequest extends BillingManualAdjustmentRequest {
  orgId: string;
}

export interface PlatformBillingRefundRequest extends BillingRefundRequest {
  orgId: string;
}

export interface PlatformBillingRefundReconcileRequest extends BillingRefundReconcileRequest {
  orgId: string;
}

export function parsePlatformBillingLookupRequest(query: unknown): PlatformBillingLookupRequest {
  const obj = requireQueryObject(query, createParseError);
  const orgId = readOptionalQueryStringField(obj, 'orgId');
  const projectId = readOptionalQueryStringField(obj, 'projectId');
  if (!orgId && !projectId) {
    throw new ConsoleBillingError(
      'invalid_query',
      400,
      'Query parameter orgId or projectId is required',
    );
  }
  return {
    ...(orgId ? { orgId } : {}),
    ...(projectId ? { projectId } : {}),
    activity: parseBillingAccountActivityRequest(query),
  };
}

export function parsePlatformBillingSearchRequest(
  query: unknown,
): PlatformBillingOrganizationSearchRequest {
  const obj = requireQueryObject(query, createParseError);
  return {
    query: readOptionalQueryStringField(obj, 'query') || '',
    limit: normalizePlatformBillingSearchLimit((obj as Record<string, unknown>).limit),
  };
}

export function parsePlatformBillingManualAdjustmentRequest(
  body: unknown,
): PlatformBillingManualAdjustmentRequest {
  const obj = requireBodyObject(body, createParseError);
  const orgId = readRequiredStringField(obj, 'orgId', createParseError).trim();
  const request = parseBillingManualAdjustmentRequest(body);
  return {
    orgId,
    ...request,
  };
}

export function parsePlatformBillingRefundRequest(body: unknown): PlatformBillingRefundRequest {
  const obj = requireBodyObject(body, createParseError);
  return {
    orgId: readRequiredStringField(obj, 'orgId', createParseError).trim(),
    ...parseBillingRefundRequest(body),
  };
}

export function parsePlatformBillingRefundReconcileRequest(
  body: unknown,
): PlatformBillingRefundReconcileRequest {
  const obj = requireBodyObject(body, createParseError);
  return {
    orgId: readRequiredStringField(obj, 'orgId', createParseError).trim(),
    ...parseBillingRefundReconcileRequest(body),
  };
}

export async function resolvePlatformBillingLookup(input: {
  claims: ConsoleAuthClaims;
  billing: ConsoleBillingService;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  request: PlatformBillingLookupRequest;
}): Promise<PlatformBillingLookupResult> {
  const requestedOrgId = String(input.request.orgId || '').trim();
  const requestedProjectId = String(input.request.projectId || '').trim();

  const resolvedBy: PlatformBillingLookupResult['resolvedBy'] = requestedProjectId
    ? 'project_id'
    : 'org_id';
  let targetOrgId = requestedOrgId;

  if (requestedProjectId) {
    const projectOrganization = await input.orgProjectEnv.findOrganizationForScope({
      projectId: requestedProjectId,
    });
    if (!projectOrganization) {
      throw new ConsoleBillingError(
        'project_not_found',
        404,
        `Project ${requestedProjectId} was not found`,
      );
    }
    if (requestedOrgId && projectOrganization.id !== requestedOrgId) {
      throw new ConsoleBillingError(
        'platform_billing_scope_mismatch',
        409,
        `Project ${requestedProjectId} does not belong to organization ${requestedOrgId}`,
      );
    }
    targetOrgId = projectOrganization.id;
  }

  if (!targetOrgId) {
    throw new ConsoleBillingError(
      'invalid_query',
      400,
      'Resolved platform billing target is missing organization scope',
    );
  }

  const readCtx = toPlatformLookupReadContext(input.claims, targetOrgId);
  const organization = await input.orgProjectEnv.getOrganization(readCtx);
  let project: ConsoleProject | null = null;
  if (requestedProjectId) {
    const projects = await input.orgProjectEnv.listProjects(readCtx);
    project = projects.find((entry) => entry.id === requestedProjectId) || null;
    if (!project) {
      throw new ConsoleBillingError(
        'project_not_found',
        404,
        `Project ${requestedProjectId} was not found`,
      );
    }
  }

  const billingCtx = toPlatformBillingContext(input.claims, targetOrgId);
  const [overview, activity, refunds] = await Promise.all([
    input.billing.getOverview(billingCtx),
    input.billing.listAccountActivity(billingCtx, input.request.activity),
    input.billing.listRefunds(billingCtx),
  ]);

  return {
    resolvedBy,
    organization,
    project,
    overview,
    activity,
    refunds,
  };
}

export async function searchPlatformBillingOrganizations(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService;
  request: PlatformBillingOrganizationSearchRequest;
}): Promise<ConsoleOrganization[]> {
  return input.orgProjectEnv.searchOrganizations(input.request);
}

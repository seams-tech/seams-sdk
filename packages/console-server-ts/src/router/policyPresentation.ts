import type { ConsolePolicyKind } from '@seams-internal/console-server/policies';
import type { ConsolePolicyService } from '@seams-internal/console-server/policies/service';

export interface ConsolePolicyPresentation {
  policyId: string | null;
  policyName: string | null;
  policyKind: ConsolePolicyKind | null;
}

export type ConsolePolicyPresentationLookup = Record<
  string,
  {
    policyName: string | null;
    policyKind: ConsolePolicyKind | null;
  }
>;

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function readMetadata(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return raw as Record<string, unknown>;
}

function normalizePolicyKind(value: unknown): ConsolePolicyKind | null {
  const out = normalizeString(value).toUpperCase();
  if (out === 'TRANSACTION' || out === 'GAS_SPONSORSHIP') return out;
  return null;
}

export async function listConsolePolicyPresentationLookup(
  policies: ConsolePolicyService | null | undefined,
  ctx: { orgId: string; actorUserId: string; roles: string[] },
): Promise<ConsolePolicyPresentationLookup> {
  if (!policies) return {};
  const rows = await policies.listPolicies(ctx);
  const lookup: ConsolePolicyPresentationLookup = {};
  for (const row of rows) {
    const policyId = normalizeString(row.id);
    if (!policyId) continue;
    lookup[policyId] = {
      policyName: normalizeString(row.name) || policyId,
      policyKind: row.kind || null,
    };
  }
  return lookup;
}

export async function resolveConsolePolicyPresentation(
  policies: ConsolePolicyService | null | undefined,
  ctx: { orgId: string; actorUserId: string; roles: string[] },
  policyIdRaw: unknown,
): Promise<ConsolePolicyPresentation> {
  const policyId = normalizeString(policyIdRaw);
  if (!policyId) {
    return {
      policyId: null,
      policyName: null,
      policyKind: null,
    };
  }
  if (!policies) {
    return {
      policyId,
      policyName: null,
      policyKind: null,
    };
  }
  const policy = await policies.getPolicy(ctx, policyId);
  return {
    policyId,
    policyName: policy ? normalizeString(policy.name) || policy.id : null,
    policyKind: policy?.kind || null,
  };
}

export function projectConsolePolicyPresentation(input: {
  resourceType?: unknown;
  resourceId?: unknown;
  metadata?: unknown;
  policyPresentationLookup?: Readonly<ConsolePolicyPresentationLookup>;
}): ConsolePolicyPresentation {
  const metadata = readMetadata(input.metadata);
  const resourceType = normalizeString(input.resourceType ?? metadata.resourceType).toUpperCase();
  const resourceId = normalizeString(input.resourceId ?? metadata.resourceId);
  const policyId = normalizeString(metadata.policyId) || (resourceType === 'POLICY' ? resourceId : '');
  const policyPresentation = policyId ? input.policyPresentationLookup?.[policyId] : undefined;
  const policyName =
    normalizeString(metadata.policyName) ||
    normalizeString(policyPresentation?.policyName);
  const policyKind = normalizePolicyKind(metadata.policyKind) || policyPresentation?.policyKind || null;
  return {
    policyId: policyId || null,
    policyName: policyName || null,
    policyKind,
  };
}

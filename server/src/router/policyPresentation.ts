import type { ConsolePolicyService } from '../console/policies/service';

export interface ConsolePolicyPresentation {
  policyId: string | null;
  policyName: string | null;
}

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function readMetadata(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return raw as Record<string, unknown>;
}

export async function listConsolePolicyNames(
  policies: ConsolePolicyService | null | undefined,
  ctx: { orgId: string; actorUserId: string; roles: string[] },
): Promise<Record<string, string>> {
  if (!policies) return {};
  const rows = await policies.listPolicies(ctx);
  const names: Record<string, string> = {};
  for (const row of rows) {
    const policyId = normalizeString(row.id);
    if (!policyId) continue;
    names[policyId] = normalizeString(row.name) || policyId;
  }
  return names;
}

export function projectConsolePolicyPresentation(input: {
  resourceType?: unknown;
  resourceId?: unknown;
  metadata?: unknown;
  policyNames?: Readonly<Record<string, string>>;
}): ConsolePolicyPresentation {
  const metadata = readMetadata(input.metadata);
  const resourceType = normalizeString(input.resourceType ?? metadata.resourceType).toUpperCase();
  const resourceId = normalizeString(input.resourceId ?? metadata.resourceId);
  const policyId = normalizeString(metadata.policyId) || (resourceType === 'POLICY' ? resourceId : '');
  const policyName =
    normalizeString(metadata.policyName) || (policyId ? normalizeString(input.policyNames?.[policyId]) : '');
  return {
    policyId: policyId || null,
    policyName: policyName || null,
  };
}

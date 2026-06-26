import {
  deriveConsoleOrganizationSlug,
  generateConsoleOrganizationId,
} from '@seams-internal/shared-ts/console/organizationIdentity';

export function normalizeDashboardOrganizationIdentity(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[_:\-\s]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function deriveDashboardOrganizationSlug(value: string): string {
  return deriveConsoleOrganizationSlug(value);
}

export function isDashboardDefaultOrganizationName(input: {
  name: string;
  orgId: string;
}): boolean {
  const normalizedName = normalizeDashboardOrganizationIdentity(input.name);
  const normalizedOrgId = normalizeDashboardOrganizationIdentity(input.orgId);
  if (!normalizedName || !normalizedOrgId) return false;
  return normalizedName === normalizedOrgId;
}

export function generateDashboardOrganizationId(): string {
  return generateConsoleOrganizationId();
}

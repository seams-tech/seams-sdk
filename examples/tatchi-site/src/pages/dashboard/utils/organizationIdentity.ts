export function normalizeDashboardOrganizationIdentity(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[_:\-\s]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function deriveDashboardOrganizationSlug(value: string): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
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

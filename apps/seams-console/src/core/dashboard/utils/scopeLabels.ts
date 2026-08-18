function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function inferEnvironmentKey(value: string): 'dev' | 'staging' | 'prod' | null {
  const normalized = normalizeString(value).toLowerCase();
  if (!normalized) return null;
  if (normalized === 'dev' || normalized.endsWith(':dev') || normalized.endsWith('_dev')) {
    return 'dev';
  }
  if (
    normalized === 'staging' ||
    normalized.endsWith(':staging') ||
    normalized.endsWith('_staging')
  ) {
    return 'staging';
  }
  if (normalized === 'prod' || normalized.endsWith(':prod') || normalized.endsWith('_prod')) {
    return 'prod';
  }
  return null;
}

function humanizeEnvironmentKey(key: 'dev' | 'staging' | 'prod'): string {
  if (key === 'dev') return 'Development';
  if (key === 'staging') return 'Staging';
  return 'Production';
}

function humanizeIdentifier(value: string): string {
  const normalized = normalizeString(value);
  if (!normalized) return '';
  return normalized.replace(/[_:-]+/g, ' ').replace(/\s+/g, ' ').trim();
}

export function getDashboardProjectLabel(input: {
  projectId?: string | null;
  projectName?: string | null;
}): string {
  const name = normalizeString(input.projectName);
  if (name) return name;
  const id = normalizeString(input.projectId);
  return id ? humanizeIdentifier(id) : 'No project';
}

export function getDashboardEnvironmentLabel(input: {
  environmentId?: string | null;
  environmentName?: string | null;
}): string {
  const name = normalizeString(input.environmentName);
  if (name) return name;
  const id = normalizeString(input.environmentId);
  if (!id) return 'No environment';
  const inferredKey = inferEnvironmentKey(id);
  return inferredKey ? humanizeEnvironmentKey(inferredKey) : humanizeIdentifier(id);
}

import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardAppSettings {
  environmentId: string;
  allowedOrigins: string[];
  allowedDomains: string[];
  cookie: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: string;
    domain: string | null;
    path: string;
    maxAgeSeconds: number;
  };
  jwt: {
    issuer: string;
    audience: string[];
    keyIds: string[];
    accessTokenTtlSeconds: number;
    refreshTokenTtlSeconds: number;
  };
  ssoMetadataUrl: string | null;
  updatedAt: string;
}

export interface DashboardSecuritySettings {
  environmentId: string;
  ipAllowlist: string[];
  enforceIpAllowlist: boolean;
  requireMfaForRiskyChanges: boolean;
  riskyChangeApproval: {
    approvalsRequired: number;
    requireAdmin: boolean;
    requireMfa: boolean;
  };
  updatedAt: string;
}

interface ConsoleSettingsResponse {
  ok?: boolean;
  message?: string;
  appSettings?: unknown;
  securitySettings?: unknown;
}

function decodeStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function decodeAppSettings(raw: unknown): DashboardAppSettings | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const environmentId = String(row.environmentId || '').trim();
  if (!environmentId) return null;
  const cookie =
    row.cookie && typeof row.cookie === 'object' && !Array.isArray(row.cookie)
      ? (row.cookie as Record<string, unknown>)
      : {};
  const jwt =
    row.jwt && typeof row.jwt === 'object' && !Array.isArray(row.jwt)
      ? (row.jwt as Record<string, unknown>)
      : {};
  return {
    environmentId,
    allowedOrigins: decodeStringArray(row.allowedOrigins),
    allowedDomains: decodeStringArray(row.allowedDomains),
    cookie: {
      httpOnly: cookie.httpOnly !== false,
      secure: cookie.secure !== false,
      sameSite: String(cookie.sameSite || '').trim() || 'LAX',
      domain: cookie.domain == null ? null : String(cookie.domain || '').trim() || null,
      path: String(cookie.path || '').trim() || '/',
      maxAgeSeconds: Number(cookie.maxAgeSeconds || 0),
    },
    jwt: {
      issuer: String(jwt.issuer || '').trim(),
      audience: decodeStringArray(jwt.audience),
      keyIds: decodeStringArray(jwt.keyIds),
      accessTokenTtlSeconds: Number(jwt.accessTokenTtlSeconds || 0),
      refreshTokenTtlSeconds: Number(jwt.refreshTokenTtlSeconds || 0),
    },
    ssoMetadataUrl: row.ssoMetadataUrl == null ? null : String(row.ssoMetadataUrl || '').trim() || null,
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

function decodeSecuritySettings(raw: unknown): DashboardSecuritySettings | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const environmentId = String(row.environmentId || '').trim();
  if (!environmentId) return null;
  const approval =
    row.riskyChangeApproval &&
    typeof row.riskyChangeApproval === 'object' &&
    !Array.isArray(row.riskyChangeApproval)
      ? (row.riskyChangeApproval as Record<string, unknown>)
      : {};
  return {
    environmentId,
    ipAllowlist: decodeStringArray(row.ipAllowlist),
    enforceIpAllowlist: row.enforceIpAllowlist === true,
    requireMfaForRiskyChanges: row.requireMfaForRiskyChanges !== false,
    riskyChangeApproval: {
      approvalsRequired: Number(approval.approvalsRequired || 0),
      requireAdmin: approval.requireAdmin !== false,
      requireMfa: approval.requireMfa !== false,
    },
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

export async function getDashboardAppSettings(environmentId: string): Promise<DashboardAppSettings> {
  const envId = String(environmentId || '').trim();
  if (!envId) throw new Error('Environment id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/settings/app?environmentId=${encodeURIComponent(envId)}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleSettingsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'App settings request failed'));
  }
  const appSettings = decodeAppSettings(body?.appSettings);
  if (!appSettings) throw new Error('App settings response was invalid');
  return appSettings;
}

export async function updateDashboardAppSettings(
  input: Record<string, unknown>,
): Promise<DashboardAppSettings> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/settings/app`, {
    method: 'PATCH',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleSettingsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update app settings request failed'));
  }
  const appSettings = decodeAppSettings(body?.appSettings);
  if (!appSettings) throw new Error('Update app settings response was invalid');
  return appSettings;
}

export async function getDashboardSecuritySettings(
  environmentId: string,
): Promise<DashboardSecuritySettings> {
  const envId = String(environmentId || '').trim();
  if (!envId) throw new Error('Environment id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/settings/security?environmentId=${encodeURIComponent(envId)}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleSettingsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Security settings request failed'));
  }
  const securitySettings = decodeSecuritySettings(body?.securitySettings);
  if (!securitySettings) throw new Error('Security settings response was invalid');
  return securitySettings;
}

export async function updateDashboardSecuritySettings(
  input: Record<string, unknown>,
): Promise<DashboardSecuritySettings> {
  const payload: Record<string, unknown> = { ...input };
  if (Object.prototype.hasOwnProperty.call(payload, 'approvalId')) {
    const approvalId = String(payload.approvalId || '').trim();
    if (approvalId) payload.approvalId = approvalId;
    else delete payload.approvalId;
  }
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/settings/security`, {
    method: 'PATCH',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(payload),
  });
  const body = (await parseConsoleJson(response)) as ConsoleSettingsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update security settings request failed'));
  }
  const securitySettings = decodeSecuritySettings(body?.securitySettings);
  if (!securitySettings) throw new Error('Update security settings response was invalid');
  return securitySettings;
}

import type { SwitchConsoleAccountOrganizationContextResult } from '../console/account';
import type { SessionAdapter, SessionClaims } from './routerApi';

const RESERVED_SESSION_CLAIMS = new Set([
  'sub',
  'iat',
  'exp',
  'nbf',
  'iss',
  'aud',
  'orgId',
  'projectId',
  'environmentId',
  'roles',
]);

export interface ParsedConsoleSessionForContextSwitch {
  userId: string;
  claims: SessionClaims;
}

export async function parseConsoleSessionForContextSwitch(
  session: SessionAdapter,
  headers: Record<string, string | string[] | undefined>,
): Promise<ParsedConsoleSessionForContextSwitch | null> {
  const parsed = await session.parse(headers);
  if (!parsed.ok) return null;

  const claims = parsed.claims;
  const userId = String(claims.userId || '').trim() || String(claims.sub || '').trim();
  if (!userId) return null;

  return {
    userId,
    claims,
  };
}

export function buildConsoleContextSwitchSessionClaims(
  claims: SessionClaims,
  nextContext: SwitchConsoleAccountOrganizationContextResult,
): Record<string, unknown> {
  const extraClaims: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(claims)) {
    if (RESERVED_SESSION_CLAIMS.has(key)) continue;
    extraClaims[key] = value;
  }

  extraClaims.orgId = nextContext.orgId;
  extraClaims.roles = [...nextContext.actorRoles];
  if (nextContext.projectId) {
    extraClaims.projectId = nextContext.projectId;
  }
  if (nextContext.environmentId) {
    extraClaims.environmentId = nextContext.environmentId;
  }

  return extraClaims;
}

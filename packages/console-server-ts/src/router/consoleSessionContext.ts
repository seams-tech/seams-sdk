import type { SwitchConsoleAccountOrganizationContextResult } from '@seams-internal/console-server/account';
import type { SessionAdapter, SessionClaims } from '../boundary';

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
  'membershipId',
  'authorizationVersion',
  'role',
  'adminPermissions',
  'projectAccess',
  'platformSupport',
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
  extraClaims.membershipId = nextContext.membershipId;
  extraClaims.authorizationVersion = nextContext.authorizationVersion;
  extraClaims.role = nextContext.role;
  extraClaims.adminPermissions = [...nextContext.adminPermissions];
  extraClaims.projectAccess =
    nextContext.projectAccess.kind === 'all'
      ? { kind: 'all' }
      : {
          kind: 'assigned',
          assignments: nextContext.projectAccess.assignments.map((assignment) => ({
            projectId: assignment.projectId,
            accessLevel: assignment.accessLevel,
          })),
        };
  extraClaims.platformSupport = nextContext.platformSupport;
  if (nextContext.projectId) {
    extraClaims.projectId = nextContext.projectId;
  }
  if (nextContext.environmentId) {
    extraClaims.environmentId = nextContext.environmentId;
  }

  return extraClaims;
}

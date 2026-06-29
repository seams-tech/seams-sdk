export type ConsoleRole =
  | 'owner'
  | 'admin'
  | 'platform_admin'
  | 'security_admin'
  | 'billing_admin'
  | 'developer'
  | 'support'
  | 'ops';

export interface ConsoleAuthClaims {
  userId: string;
  orgId: string;
  projectId?: string;
  environmentId?: string;
  roles: string[];
  [key: string]: unknown;
}

export type HeaderRecord = Record<string, string | string[] | undefined>;

export type ConsoleAuthAdapterResult =
  | { ok: true; claims: ConsoleAuthClaims }
  | { ok: false; code?: 'unauthorized' | 'forbidden'; message?: string; status?: 401 | 403 };

export interface ConsoleAuthAdapter {
  authenticate(headers: HeaderRecord): Promise<ConsoleAuthAdapterResult> | ConsoleAuthAdapterResult;
}

export type ConsoleAuthResult =
  | { ok: true; claims: ConsoleAuthClaims }
  | {
      ok: false;
      status: 401 | 403 | 503;
      code: 'unauthorized' | 'forbidden' | 'console_auth_not_configured';
      message: string;
    };

function normalizeRoles(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) =>
      String(item || '')
        .trim()
        .toLowerCase(),
    )
    .filter(Boolean);
}

export async function authenticateConsoleRequest(
  headers: HeaderRecord,
  auth: ConsoleAuthAdapter | null | undefined,
): Promise<ConsoleAuthResult> {
  if (!auth) {
    return {
      ok: false,
      status: 503,
      code: 'console_auth_not_configured',
      message: 'Console auth adapter is not configured on this server',
    };
  }

  const result = await auth.authenticate(headers);
  if (!result.ok) {
    const status = result.status || (result.code === 'forbidden' ? 403 : 401);
    const code = result.code || (status === 403 ? 'forbidden' : 'unauthorized');
    return {
      ok: false,
      status,
      code,
      message: result.message || (code === 'forbidden' ? 'Forbidden' : 'Unauthorized'),
    };
  }

  return {
    ok: true,
    claims: {
      ...result.claims,
      roles: normalizeRoles(result.claims.roles),
    },
  };
}

export function hasConsoleRole(claims: ConsoleAuthClaims, role: ConsoleRole | string): boolean {
  const normalizedRole = String(role || '')
    .trim()
    .toLowerCase();
  if (!normalizedRole) return false;
  return normalizeRoles(claims.roles).includes(normalizedRole);
}

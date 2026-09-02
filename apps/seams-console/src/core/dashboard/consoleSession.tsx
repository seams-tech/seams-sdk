import React from 'react';
import {
  buildConsoleAcceptHeaders,
  consoleErrorMessage,
  normalizeConsoleFetchError,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from './consoleHttp';

export interface DashboardConsoleSessionClaims {
  userId: string;
  orgId: string;
  membershipId: string;
  authorizationVersion: number;
  role: 'OWNER' | 'ADMIN' | 'MEMBER';
  adminPermissions: Array<
    'members.manage' | 'projects.manage' | 'billing.view' | 'billing.manage'
  >;
  projectAccess: Array<{
    projectId: string;
    accessLevel: 'viewer' | 'editor';
  }>;
  platformSupport: boolean;
  email?: string;
  name?: string;
  projectId?: string;
  environmentId?: string;
}

interface DashboardConsoleSessionResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  claims?: unknown;
}

interface DashboardConsoleSessionRevokeResponse {
  ok?: boolean;
  revoked?: boolean;
  code?: string;
  message?: string;
}

export interface DashboardConsoleSessionState {
  loading: boolean;
  claims: DashboardConsoleSessionClaims | null;
  errorMessage: string;
  errorCode: string;
  errorStatus: number | null;
  refresh: () => void;
}

export function canDashboardEditProject(
  claims: DashboardConsoleSessionClaims | null,
  projectId: string,
): boolean {
  if (!claims) return false;
  if (claims.role === 'OWNER' || claims.role === 'ADMIN') return true;
  return claims.projectAccess.some(
    (assignment) =>
      assignment.projectId === projectId && assignment.accessLevel === 'editor',
  );
}

export function canDashboardViewBilling(
  claims: DashboardConsoleSessionClaims | null,
): boolean {
  if (!claims) return false;
  if (claims.role === 'OWNER') return true;
  return (
    claims.role === 'ADMIN' &&
    (claims.adminPermissions.includes('billing.view') ||
      claims.adminPermissions.includes('billing.manage'))
  );
}

export function canDashboardManageBilling(
  claims: DashboardConsoleSessionClaims | null,
): boolean {
  if (!claims) return false;
  if (claims.role === 'OWNER') return true;
  return claims.role === 'ADMIN' && claims.adminPermissions.includes('billing.manage');
}

const DashboardConsoleSessionContext = React.createContext<DashboardConsoleSessionState | null>(
  null,
);

type DashboardConsoleSessionError = Error & {
  code?: string;
  status?: number;
};

function asSessionError(error: unknown): DashboardConsoleSessionError {
  if (error instanceof Error) return error as DashboardConsoleSessionError;
  return new Error(String(error)) as DashboardConsoleSessionError;
}

function parseClaims(raw: unknown): DashboardConsoleSessionClaims | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const userId = String(row.userId || '').trim();
  const orgId = String(row.orgId || '').trim();
  const membershipId = String(row.membershipId || '').trim();
  const authorizationVersion = Number(row.authorizationVersion);
  const roleRaw = String(row.role || '').trim().toUpperCase();
  const role =
    roleRaw === 'OWNER' || roleRaw === 'ADMIN' || roleRaw === 'MEMBER' ? roleRaw : null;
  if (
    !userId ||
    !orgId ||
    !membershipId ||
    !role ||
    !Number.isSafeInteger(authorizationVersion) ||
    authorizationVersion < 1
  ) {
    return null;
  }
  const permissionSet = new Set<
    'members.manage' | 'projects.manage' | 'billing.view' | 'billing.manage'
  >();
  if (Array.isArray(row.adminPermissions)) {
    for (const entry of row.adminPermissions) {
      const permission = String(entry || '').trim();
      if (
        permission === 'members.manage' ||
        permission === 'projects.manage' ||
        permission === 'billing.view' ||
        permission === 'billing.manage'
      ) {
        permissionSet.add(permission);
      }
    }
  }
  if (permissionSet.has('billing.manage')) permissionSet.add('billing.view');
  const projectAccess = Array.isArray(row.projectAccess)
    ? row.projectAccess.flatMap((entry) => {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return [];
        const access = entry as Record<string, unknown>;
        const accessProjectId = String(access.projectId || '').trim();
        const accessLevel = String(access.accessLevel || '').trim().toLowerCase();
        if (
          !accessProjectId ||
          (accessLevel !== 'viewer' && accessLevel !== 'editor')
        ) {
          return [];
        }
        const normalizedAccessLevel: 'viewer' | 'editor' = accessLevel;
        return [{ projectId: accessProjectId, accessLevel: normalizedAccessLevel }];
      })
    : [];
  const email = String(row.email || '').trim();
  const name = String(row.name || '').trim();
  const projectId = String(row.projectId || '').trim();
  const environmentId = String(row.environmentId || '').trim();
  return {
    userId,
    orgId,
    membershipId,
    authorizationVersion,
    role,
    adminPermissions: [
      'members.manage',
      'projects.manage',
      'billing.view',
      'billing.manage',
    ].filter((permission) =>
      permissionSet.has(
        permission as 'members.manage' | 'projects.manage' | 'billing.view' | 'billing.manage',
      ),
    ) as DashboardConsoleSessionClaims['adminPermissions'],
    projectAccess,
    platformSupport: row.platformSupport === true,
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
  };
}

export async function fetchDashboardConsoleSession(): Promise<DashboardConsoleSessionClaims> {
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/session`, {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/session',
      operation: 'Console session request',
    });
  }

  const body = (await parseConsoleJson(response)) as DashboardConsoleSessionResponse | null;
  if (!response.ok || body?.ok !== true) {
    const message = consoleErrorMessage(response, body, 'Console session request failed');
    const code = String(body?.code || '').trim();
    const error = new Error(message) as DashboardConsoleSessionError;
    error.code =
      code ||
      (response.status === 403
        ? 'forbidden'
        : response.status === 401
          ? 'unauthorized'
          : '');
    error.status = response.status;
    throw error;
  }
  const claims = parseClaims(body.claims);
  if (!claims) {
    throw new Error('Console session response did not include valid claims');
  }
  return claims;
}

export async function revokeDashboardConsoleSession(): Promise<void> {
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/auth/revoke`, {
      method: 'POST',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/auth/revoke',
      operation: 'Console session revoke request',
    });
  }

  const body = (await parseConsoleJson(response)) as DashboardConsoleSessionRevokeResponse | null;
  if (response.ok && body?.ok === true) {
    return;
  }
  if (response.status === 401) {
    return;
  }
  throw new Error(consoleErrorMessage(response, body, 'Console session revoke failed'));
}

const CONSOLE_SIGN_OUT_FLAG_KEY = 'seams.console.signedOut';

/**
 * Records that the user explicitly signed out. The login page consumes this to
 * skip its auto-resume redirect: if a revoke fails server-side the cookie is
 * still valid, and without the flag the login page would bounce the user
 * straight back into the console they just left.
 */
export function markDashboardConsoleSignOut(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(CONSOLE_SIGN_OUT_FLAG_KEY, '1');
  } catch {}
}

/** Reads and clears the sign-out flag; true only for the first read after a sign-out. */
export function consumeDashboardConsoleSignOut(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const raw = window.sessionStorage.getItem(CONSOLE_SIGN_OUT_FLAG_KEY);
    if (!raw) return false;
    window.sessionStorage.removeItem(CONSOLE_SIGN_OUT_FLAG_KEY);
    return true;
  } catch {
    return false;
  }
}

export function DashboardConsoleSessionProvider({
  children,
}: {
  children: React.ReactNode;
}): React.JSX.Element {
  const [loading, setLoading] = React.useState<boolean>(true);
  const [claims, setClaims] = React.useState<DashboardConsoleSessionClaims | null>(null);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [errorCode, setErrorCode] = React.useState<string>('');
  const [errorStatus, setErrorStatus] = React.useState<number | null>(null);

  const refresh = React.useCallback(() => {
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    setErrorCode('');
    setErrorStatus(null);
    fetchDashboardConsoleSession()
      .then((nextClaims) => {
        if (cancelled) return;
        setClaims(nextClaims);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const parsed = asSessionError(error);
        setClaims(null);
        setErrorMessage(parsed.message || String(error));
        setErrorCode(String(parsed.code || '').trim());
        setErrorStatus(typeof parsed.status === 'number' ? parsed.status : null);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  React.useEffect(() => {
    const cleanup = refresh();
    return cleanup;
  }, [refresh]);

  const value = React.useMemo<DashboardConsoleSessionState>(
    () => ({
      loading,
      claims,
      errorMessage,
      errorCode,
      errorStatus,
      refresh: () => {
        refresh();
      },
    }),
    [claims, errorCode, errorMessage, errorStatus, loading, refresh],
  );

  return (
    <DashboardConsoleSessionContext.Provider value={value}>
      {children}
    </DashboardConsoleSessionContext.Provider>
  );
}

export function useDashboardConsoleSession(): DashboardConsoleSessionState {
  const context = React.useContext(DashboardConsoleSessionContext);
  if (context) return context;
  return {
    loading: false,
    claims: null,
    errorMessage: 'Console session context is unavailable',
    errorCode: 'console_session_context_unavailable',
    errorStatus: null,
    refresh: () => {},
  };
}

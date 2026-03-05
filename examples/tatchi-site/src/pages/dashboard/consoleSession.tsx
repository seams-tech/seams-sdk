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
  roles: string[];
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
  if (!userId || !orgId) return null;
  const roles = Array.isArray(row.roles)
    ? row.roles.map((entry) => String(entry || '').trim()).filter(Boolean)
    : [];
  const projectId = String(row.projectId || '').trim();
  const environmentId = String(row.environmentId || '').trim();
  return {
    userId,
    orgId,
    roles,
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
    response = await fetch(`${base}/session/revoke`, {
      method: 'POST',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/session/revoke',
      operation: 'Session revoke request',
    });
  }

  const body = (await parseConsoleJson(response)) as DashboardConsoleSessionRevokeResponse | null;
  if (response.ok && body?.ok === true) {
    return;
  }
  if (response.status === 401) {
    return;
  }
  throw new Error(consoleErrorMessage(response, body, 'Session revoke failed'));
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

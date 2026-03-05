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

export interface DashboardConsoleSessionState {
  loading: boolean;
  claims: DashboardConsoleSessionClaims | null;
  errorMessage: string;
  refresh: () => void;
}

const DashboardConsoleSessionContext = React.createContext<DashboardConsoleSessionState | null>(
  null,
);

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

async function fetchDashboardConsoleSession(): Promise<DashboardConsoleSessionClaims> {
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
    throw new Error(consoleErrorMessage(response, body, 'Console session request failed'));
  }
  const claims = parseClaims(body.claims);
  if (!claims) {
    throw new Error('Console session response did not include valid claims');
  }
  return claims;
}

export function DashboardConsoleSessionProvider({
  children,
}: {
  children: React.ReactNode;
}): React.JSX.Element {
  const [loading, setLoading] = React.useState<boolean>(true);
  const [claims, setClaims] = React.useState<DashboardConsoleSessionClaims | null>(null);
  const [errorMessage, setErrorMessage] = React.useState<string>('');

  const refresh = React.useCallback(() => {
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    fetchDashboardConsoleSession()
      .then((nextClaims) => {
        if (cancelled) return;
        setClaims(nextClaims);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setClaims(null);
        setErrorMessage(error instanceof Error ? error.message : String(error));
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
      refresh: () => {
        refresh();
      },
    }),
    [claims, errorMessage, loading, refresh],
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
    refresh: () => {},
  };
}

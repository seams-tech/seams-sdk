import React from 'react';
import { FRONTEND_CONFIG } from '@/config';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  ensureGoogleIdentityScriptLoaded,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';
import { fetchDashboardConsoleSession } from '../consoleSession';
import '../styles.css';

interface GoogleOptionsResponse {
  ok?: boolean;
  configured?: boolean;
  message?: string;
}

function normalizeBaseUrl(input: unknown): string {
  return String(input || '').trim().replace(/\/+$/, '');
}

async function parseOptionalJson(response: Response): Promise<any> {
  return response.json().catch(() => null);
}

export function DashboardLoginPage(): React.JSX.Element {
  const { go, linkProps } = useSiteRouter();
  const homeProps = linkProps('/');
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.consoleBaseUrl || FRONTEND_CONFIG.relayerUrl),
    [],
  );
  const googleClientId = React.useMemo(
    () => String(FRONTEND_CONFIG.googleOidcClientId || '').trim(),
    [],
  );
  const [initializing, setInitializing] = React.useState<boolean>(true);
  const [loading, setLoading] = React.useState<boolean>(false);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [googleConfigured, setGoogleConfigured] = React.useState<boolean>(false);

  React.useEffect(() => {
    let cancelled = false;
    fetchDashboardConsoleSession()
      .then(() => {
        if (cancelled) return;
        go('/dashboard');
      })
      .catch(() => {})
      .finally(() => {
        if (cancelled) return;
        setInitializing(false);
      });
    return () => {
      cancelled = true;
    };
  }, [go]);

  React.useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (!relayerBaseUrl || !googleClientId) {
        if (!cancelled) setGoogleConfigured(false);
        return;
      }
      try {
        const response = await fetch(`${relayerBaseUrl}/auth/google/options`, {
          method: 'POST',
          credentials: 'include',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({}),
        });
        const body = (await parseOptionalJson(response)) as GoogleOptionsResponse | null;
        const configured = response.ok && body?.ok === true && body?.configured === true;
        if (!cancelled) setGoogleConfigured(configured);
      } catch {
        if (!cancelled) setGoogleConfigured(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [googleClientId, relayerBaseUrl]);

  const onGoogleSignIn = React.useCallback(async () => {
    if (loading) return;
    setLoading(true);
    setErrorMessage('');
    try {
      if (!relayerBaseUrl) {
        throw new Error('Relayer base URL is not configured');
      }
      if (!googleClientId) {
        throw new Error('Google client ID is not configured in frontend env');
      }
      if (!googleConfigured) {
        throw new Error('Google OIDC is not configured on the relay server');
      }

      await ensureGoogleIdentityScriptLoaded();
      const idToken = await requestGoogleIdToken(googleClientId);

      const response = await fetch(`${relayerBaseUrl}/session/exchange`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          session_kind: 'cookie',
          exchange: {
            type: 'oidc_jwt',
            token: idToken,
          },
        }),
      });
      const body = await parseOptionalJson(response);
      if (!response.ok || body?.ok !== true) {
        const message = String(body?.message || '').trim();
        throw new Error(message || `Google session exchange failed (${response.status})`);
      }

      await fetchDashboardConsoleSession();
      go('/dashboard');
    } catch (error: unknown) {
      setErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setLoading(false);
    }
  }, [go, googleClientId, googleConfigured, loading, relayerBaseUrl]);

  return (
    <main className="dashboard-login" aria-label="Dashboard login page">
      <section className="dashboard-login__card">
        <p className="dashboard-login__eyebrow">Dashboard</p>
        <h1 className="dashboard-login__title">Sign in with Google</h1>
        <p className="dashboard-login__copy">
          Use Google SSO to create a relay app session and open the console dashboard.
        </p>
        <div className="dashboard-login__actions">
          <button
            type="button"
            className="dashboard-pagination-button dashboard-login__button"
            onClick={() => {
              void onGoogleSignIn();
            }}
            disabled={initializing || loading || !googleConfigured}
          >
            {initializing
              ? 'Checking existing session...'
              : loading
                ? 'Signing in with Google...'
                : !googleClientId
                  ? 'Google client ID missing'
                  : !googleConfigured
                    ? 'Google SSO not configured'
                    : 'Continue with Google'}
          </button>
          <a className="dashboard-inline-link" href={homeProps.href} onClick={homeProps.onClick}>
            Back to site
          </a>
        </div>
        {errorMessage ? (
          <p className="dashboard-pagination-note dashboard-login__error" role="alert">
            {errorMessage}
          </p>
        ) : null}
      </section>
    </main>
  );
}

export default DashboardLoginPage;

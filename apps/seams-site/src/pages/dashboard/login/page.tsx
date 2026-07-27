import React from 'react';
import { BookOpen } from 'lucide-react';
import { FRONTEND_CONFIG } from '@/config';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { DashboardGoogleAuthCard } from '@/shared/auth/DashboardGoogleAuthCard';
import SeamsWordmark from '@/components/icons/SeamsWordmark';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';
import { fetchDashboardConsoleSession } from '../consoleSession';
import '../styles.css';

function normalizeBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

async function parseOptionalJson(response: Response): Promise<any> {
  return response.json().catch(() => null);
}

export function DashboardLoginPage(): React.JSX.Element {
  const { go, linkProps } = useSiteRouter();
  const homeProps = linkProps('/');
  const docsProps = linkProps('/docs');
  const contactProps = linkProps('/contact');
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.consoleBaseUrl || FRONTEND_CONFIG.relayerUrl),
    [],
  );
  const [googleClientId, setGoogleClientId] = React.useState<string>('');
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
      if (!relayerBaseUrl) {
        if (!cancelled) setGoogleConfigured(false);
        return;
      }
      try {
        const options = await fetchGoogleAuthOptions(relayerBaseUrl);
        if (cancelled) return;
        setGoogleClientId(options.clientId || '');
        setGoogleConfigured(options.configured);
      } catch {
        if (!cancelled) {
          setGoogleClientId('');
          setGoogleConfigured(false);
        }
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [relayerBaseUrl]);

  const onGoogleSignIn = React.useCallback(async () => {
    if (loading) return;
    setLoading(true);
    setErrorMessage('');
    try {
      if (!relayerBaseUrl) {
        throw new Error('Relayer base URL is not configured');
      }
      if (!googleClientId) {
        throw new Error('Google client ID is not configured on the Router API server');
      }
      if (!googleConfigured) {
        throw new Error('Google OIDC is not configured on the Router API server');
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
            provider: 'google',
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

  const ctaLabel = initializing
    ? 'Checking existing session...'
    : loading
      ? 'Signing in with Google...'
      : !googleClientId
        ? 'Google SSO unavailable'
        : !googleConfigured
          ? 'Google SSO not configured'
          : 'Continue with Google';

  const footerNote = googleConfigured
    ? 'Google signs you into the dashboard first. Wallet passkeys are created later inside the console.'
    : 'Set GOOGLE_OIDC_CLIENT_ID or GOOGLE_OIDC_CLIENT_IDS on the relay to enable dashboard sign-in.';

  return (
    <main className="dashboard-login" aria-label="Dashboard login page">
      {/* Split layout: the sign-in column carries the whole flow, the aside is
          static product framing that collapses away under 900px. */}
      <section className="dashboard-login__panel">
        <a
          className="dashboard-login__brand"
          href={homeProps.href}
          onClick={homeProps.onClick}
          aria-label="Seams home"
        >
          <SeamsWordmark height={24} theme="light" />
          <span className="dashboard-login__brand-label">Console</span>
        </a>
        <div className="dashboard-login__body">
          <DashboardGoogleAuthCard
            classNames={{
              root: 'dashboard-login__form',
              header: 'dashboard-login__form-header',
              heading: 'dashboard-login__form-heading',
              eyebrow: 'dashboard-login__form-eyebrow',
              copy: 'dashboard-login__form-copy',
              ctaButton: 'dashboard-login__google-button',
              ctaIcon: 'dashboard-login__google-button-icon',
              note: 'dashboard-login__form-note',
              error: 'dashboard-login__form-error',
            }}
            titleId="dashboard-login-title"
            titleTag="h1"
            title="Welcome back"
            description="Sign in to the Seams console"
            continueLabel={ctaLabel}
            continueDisabled={initializing || loading || !googleConfigured}
            onContinue={() => {
              void onGoogleSignIn();
            }}
            note={footerNote}
            errorMessage={errorMessage}
          />
        </div>
        <p className="dashboard-login__legal">
          Don&rsquo;t have console access?{' '}
          <a href={contactProps.href} onClick={contactProps.onClick}>
            Contact sales
          </a>
          .
        </p>
      </section>
      <aside className="dashboard-login__aside" aria-label="About Seams">
        <a
          className="dashboard-login__aside-link"
          href={docsProps.href}
          onClick={docsProps.onClick}
        >
          <BookOpen size={16} aria-hidden />
          <span>Documentation</span>
        </a>
        <div className="dashboard-login__aside-body">
          <p className="dashboard-login__statement">Commerce accounts for people and AI agents</p>
          <p className="dashboard-login__statement-sub">
            Auth, wallets, credentials, and delegated access in one SDK. Policy checks every action
            before it runs.
          </p>
          <span className="dashboard-login__aside-mark">
            <SeamsWordmark height={20} theme="light" />
          </span>
        </div>
      </aside>
    </main>
  );
}

export default DashboardLoginPage;

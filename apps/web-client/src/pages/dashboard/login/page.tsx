import React from 'react';
import { X } from 'lucide-react';
import { FRONTEND_CONFIG } from '@/config';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { DashboardGoogleAuthCard } from '@/shared/auth/DashboardGoogleAuthCard';
import SeamsLogo from '@/components/icons/SeamsLogo';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';
import '@/components/Navbar/Navbar.css';
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
      <a
        className="dashboard-login__brand"
        href={homeProps.href}
        onClick={homeProps.onClick}
        aria-label="Seams home"
      >
        <SeamsLogo size={44} />
        <span>Seams Console</span>
      </a>
      <DashboardGoogleAuthCard
        classNames={{
          root: 'navbar-static__auth-modal',
          header: 'navbar-static__auth-header',
          heading: 'navbar-static__auth-heading',
          eyebrow: 'navbar-static__auth-eyebrow',
          copy: 'navbar-static__auth-copy',
          provider: 'navbar-static__auth-provider',
          providerIcon: 'navbar-static__auth-provider-icon',
          providerBody: 'navbar-static__auth-provider-body',
          providerLabel: 'navbar-static__auth-provider-label',
          providerCopy: 'navbar-static__auth-provider-copy',
          ctaButton: 'navbar-static__auth-google-button',
          ctaIcon: 'navbar-static__auth-google-button-icon',
          note: 'navbar-static__auth-note',
          error: 'navbar-static__auth-error',
        }}
        titleId="dashboard-login-title"
        titleTag="h1"
        title="Sign In With Google"
        description="Use Google SSO to enter the console. Wallet passkeys can be added later inside the dashboard when you create wallets for stablecoin billing."
        providerLabel="Google SSO"
        providerDescription="One secure sign-in to open the dashboard and start managing billing."
        continueLabel={ctaLabel}
        continueDisabled={initializing || loading || !googleConfigured}
        onContinue={() => {
          void onGoogleSignIn();
        }}
        note={footerNote}
        errorMessage={errorMessage}
        closeControl={
          <a
            className="navbar-static__auth-close"
            href={homeProps.href}
            onClick={homeProps.onClick}
            aria-label="Back to site"
          >
            <X size={18} aria-hidden />
          </a>
        }
      />
    </main>
  );
}

export default DashboardLoginPage;

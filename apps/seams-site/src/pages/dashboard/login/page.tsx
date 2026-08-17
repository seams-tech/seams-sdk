import React from 'react';
import { BookOpen } from 'lucide-react';
import { getActiveFrontendDeployment } from '@/context/frontendRuntime';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { DashboardAuthCard, type DashboardAuthProvider } from '@/shared/auth/DashboardAuthCard';
import SeamsWordmark from '@/components/icons/SeamsWordmark';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';
import {
  beginGithubOAuth,
  consumeGithubOAuthCallback,
  fetchGithubOAuthOptions,
  type GithubOAuthOptions,
} from '@/shared/auth/githubOAuth';
import { consumeDashboardConsoleSignOut, fetchDashboardConsoleSession } from '../consoleSession';
import '../styles.css';

function normalizeBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function parseOptionalJson(response: Response): Promise<Record<string, unknown> | null> {
  const value: unknown = await response.json().catch(() => null);
  return isRecord(value) ? value : null;
}

type DashboardLoginCommand =
  | { readonly kind: 'google'; readonly idToken: string }
  | { readonly kind: 'github'; readonly code: string };

function assertNeverDashboardLogin(command: never): never {
  throw new Error(`Unsupported dashboard login command: ${String(command)}`);
}

async function exchangeDashboardSession(
  relayerBaseUrl: string,
  command: DashboardLoginCommand,
): Promise<void> {
  let path: string;
  let body: { readonly idToken: string } | { readonly code: string };
  let providerLabel: string;
  switch (command.kind) {
    case 'google':
      path = '/console/auth/google';
      body = { idToken: command.idToken };
      providerLabel = 'Google';
      break;
    case 'github':
      path = '/console/auth/github';
      body = { code: command.code };
      providerLabel = 'GitHub';
      break;
    default:
      return assertNeverDashboardLogin(command);
  }
  const response = await fetch(`${relayerBaseUrl}${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const responseBody = await parseOptionalJson(response);
  if (!response.ok || responseBody?.ok !== true) {
    const message = String(responseBody?.message || '').trim();
    throw new Error(message || `${providerLabel} session exchange failed (${response.status})`);
  }
}

function authConfigurationNote(input: {
  googleConfigured: boolean;
  githubConfigured: boolean;
}): string {
  if (input.googleConfigured && input.githubConfigured) return '';
  if (!input.googleConfigured && !input.githubConfigured) {
    return 'Configure Google OIDC or GitHub OAuth on the relay to enable dashboard sign-in.';
  }
  return input.googleConfigured
    ? 'Configure GitHub OAuth on the relay to enable GitHub sign-in.'
    : 'Configure Google OIDC on the relay to enable Google sign-in.';
}

export function DashboardLoginPage(): React.JSX.Element {
  const { go, linkProps } = useSiteRouter();
  const homeProps = linkProps('/');
  const docsProps = linkProps('/docs');
  const contactProps = linkProps('/contact');
  const relayerBaseUrl = React.useMemo(() => {
    const deployment = getActiveFrontendDeployment();
    return normalizeBaseUrl(deployment.consoleBaseUrl || deployment.relayerUrl);
  }, []);
  const [googleClientId, setGoogleClientId] = React.useState<string>('');
  const [githubOptions, setGithubOptions] = React.useState<GithubOAuthOptions>({
    configured: false,
  });
  const [initializing, setInitializing] = React.useState<boolean>(true);
  const [loadingProvider, setLoadingProvider] = React.useState<'google' | 'github' | null>(null);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [googleConfigured, setGoogleConfigured] = React.useState<boolean>(false);
  const [signedOut, setSignedOut] = React.useState<boolean>(false);

  React.useEffect(() => {
    let cancelled = false;
    /* Arriving here from an explicit sign-out: never auto-resume, even if the
       session still validates (a revoke can fail server-side). Otherwise the
       user is thrown straight back into the console they just left. */
    if (consumeDashboardConsoleSignOut()) {
      setSignedOut(true);
      setInitializing(false);
      return () => {
        cancelled = true;
      };
    }
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
        if (!cancelled) {
          setGoogleConfigured(false);
          setGithubOptions({ configured: false });
        }
        return;
      }
      try {
        const [googleOptions, nextGithubOptions] = await Promise.all([
          fetchGoogleAuthOptions(relayerBaseUrl),
          fetchGithubOAuthOptions(relayerBaseUrl),
        ]);
        if (cancelled) return;
        setGoogleClientId(googleOptions.clientId || '');
        setGoogleConfigured(googleOptions.configured);
        setGithubOptions(nextGithubOptions);
      } catch {
        if (!cancelled) {
          setGoogleClientId('');
          setGoogleConfigured(false);
          setGithubOptions({ configured: false });
        }
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [relayerBaseUrl]);

  React.useEffect(() => {
    const callback = consumeGithubOAuthCallback();
    if (callback.kind === 'none') return;
    if (callback.kind === 'error') {
      setErrorMessage(callback.message);
      return;
    }
    if (!relayerBaseUrl) {
      setErrorMessage('Relayer base URL is not configured');
      return;
    }
    let cancelled = false;
    setLoadingProvider('github');
    setErrorMessage('');
    exchangeDashboardSession(relayerBaseUrl, { kind: 'github', code: callback.code })
      .then(fetchDashboardConsoleSession)
      .then(() => {
        if (!cancelled) go('/dashboard');
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setErrorMessage(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingProvider(null);
      });
    return () => {
      cancelled = true;
    };
  }, [go, relayerBaseUrl]);

  const onGoogleSignIn = React.useCallback(async () => {
    if (loadingProvider) return;
    setLoadingProvider('google');
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

      await exchangeDashboardSession(relayerBaseUrl, { kind: 'google', idToken });

      await fetchDashboardConsoleSession();
      go('/dashboard');
    } catch (error: unknown) {
      setErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setLoadingProvider(null);
    }
  }, [go, googleClientId, googleConfigured, loadingProvider, relayerBaseUrl]);

  const googleLabel = initializing
    ? 'Checking existing session...'
    : loadingProvider === 'google'
      ? 'Signing in with Google...'
      : !googleClientId
        ? 'Google SSO unavailable'
        : !googleConfigured
          ? 'Google SSO not configured'
          : 'Continue with Google';

  const onGithubSignIn = React.useCallback(() => {
    if (loadingProvider || !githubOptions.configured) return;
    setErrorMessage('');
    beginGithubOAuth(githubOptions);
  }, [githubOptions, loadingProvider]);

  const githubLabel =
    loadingProvider === 'github'
      ? 'Signing in with GitHub...'
      : githubOptions.configured
        ? 'Continue with GitHub'
        : 'GitHub sign-in unavailable';
  const authBusy = initializing || loadingProvider !== null;
  const providers: readonly DashboardAuthProvider[] = [
    {
      id: 'google',
      label: googleLabel,
      disabled: authBusy || !googleConfigured,
      onContinue: onGoogleSignIn,
    },
    {
      id: 'github',
      label: githubLabel,
      disabled: authBusy || !githubOptions.configured,
      onContinue: onGithubSignIn,
    },
  ];
  const footerNote = authConfigurationNote({
    googleConfigured,
    githubConfigured: githubOptions.configured,
  });

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
          <SeamsWordmark height={24} />
          <span className="dashboard-login__brand-label">Console</span>
        </a>
        <div className="dashboard-login__body">
          <DashboardAuthCard
            classNames={{
              root: 'dashboard-login__form',
              header: 'dashboard-login__form-header',
              heading: 'dashboard-login__form-heading',
              copy: 'dashboard-login__form-copy',
              ctaGroup: 'dashboard-login__provider-buttons',
              ctaButton: 'dashboard-login__auth-button',
              ctaIcon: 'dashboard-login__auth-button-icon',
              note: 'dashboard-login__form-note',
              error: 'dashboard-login__form-error',
            }}
            titleId="dashboard-login-title"
            title={signedOut ? 'Signed out' : 'Welcome back'}
            description={
              signedOut
                ? 'You have been signed out of the Seams console.'
                : 'Sign in to the Seams console'
            }
            providers={providers}
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
          <p className="dashboard-login__statement">Wallets for people and AI agents</p>
          <p className="dashboard-login__statement-sub">
            Auth, wallets, credentials, and delegated access in one SDK. Policy checks every action
            before it runs.
          </p>
          <span className="dashboard-login__aside-mark">
            <SeamsWordmark height={20} />
          </span>
        </div>
      </aside>
    </main>
  );
}

export default DashboardLoginPage;

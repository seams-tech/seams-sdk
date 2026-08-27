import {
  AuthMenuMode,
  HostedSeamsAuthMenu,
  useSeams,
  type HostedAuthMenuExternalAuthEvidence,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuMode,
  type HostedAuthMenuOutcome,
} from '@seams/wallet/react';
import React from 'react';
import { toast } from 'sonner';

import './PasskeyLoginMenu.css';
import { FRONTEND_CONFIG } from '@/config';
import { showCopiedDemoEmailOtpToast } from './demoEmailOtpToast';
import {
  cancelGoogleIdTokenRequest,
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';

type HostedPasskeyLoginMenuProps = {
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
};

const HOSTED_AUTH_MENU_ERROR_EVENT = 'seams:hosted-auth-menu-error';

type HostedAuthMenuErrorEventDetail = {
  readonly kind: 'hosted_auth_menu_error_v1';
  readonly mode: 'login' | 'register';
  readonly message: string;
};

function hostedModeFromReactMode(mode: AuthMenuMode | undefined): HostedAuthMenuMode {
  return mode === AuthMenuMode.Register ? 'register' : 'login';
}

type GoogleSsoReadiness =
  | { kind: 'checking' }
  | { kind: 'ready'; clientId: string }
  | { kind: 'unavailable'; message: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

function formatGoogleBrokerError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  if (typeof error === 'string' && error.trim()) return error.trim();
  return 'Google SSO is unavailable. Please retry.';
}

function parseHostedAuthMenuErrorEvent(event: Event): HostedAuthMenuErrorEventDetail | null {
  if (!(event instanceof CustomEvent) || !isRecord(event.detail)) return null;
  const detail = event.detail;
  if (
    detail.kind !== 'hosted_auth_menu_error_v1' ||
    (detail.mode !== 'login' && detail.mode !== 'register') ||
    typeof detail.message !== 'string' ||
    !detail.message.trim()
  ) {
    return null;
  }
  return { kind: detail.kind, mode: detail.mode, message: detail.message.trim() };
}

function handleHostedAuthMenuError(event: Event): void {
  const error = parseHostedAuthMenuErrorEvent(event);
  if (!error) return;
  console.error(`[SeamsAuthMenu:${error.mode}]`, new Error(error.message));
  toast.error(error.message, { id: error.mode === 'register' ? 'registration' : 'login' });
}

function noop(): void {}

function subscribeToHostedAuthMenuErrors(
  containerRef: React.RefObject<HTMLDivElement | null>,
): () => void {
  const container = containerRef.current;
  if (!container) return noop;
  container.addEventListener(HOSTED_AUTH_MENU_ERROR_EVENT, handleHostedAuthMenuError);
  return container.removeEventListener.bind(
    container,
    HOSTED_AUTH_MENU_ERROR_EVENT,
    handleHostedAuthMenuError,
  );
}

function requirePreparedGoogleSsoClientId(readiness: GoogleSsoReadiness): string {
  switch (readiness.kind) {
    case 'ready':
      return readiness.clientId;
    case 'checking':
      throw new Error('Google SSO is still loading. Try again in a moment.');
    case 'unavailable':
      throw new Error(readiness.message);
    default: {
      const exhaustive: never = readiness;
      throw new Error(`Unknown Google SSO readiness state: ${JSON.stringify(exhaustive)}`);
    }
  }
}

async function prepareGoogleSsoReadiness(relayerBaseUrl: string): Promise<GoogleSsoReadiness> {
  if (!relayerBaseUrl) {
    return { kind: 'unavailable', message: 'Relayer base URL is not configured' };
  }

  const googleOptions = await fetchGoogleAuthOptions(relayerBaseUrl);
  if (!googleOptions.configured || !googleOptions.clientId) {
    return {
      kind: 'unavailable',
      message: 'Google SSO is not configured on the Router API server',
    };
  }

  await ensureGoogleIdentityScriptLoaded();
  return { kind: 'ready', clientId: googleOptions.clientId };
}

function outcomeMessage(outcome: Extract<HostedAuthMenuOutcome, { kind: 'failed' }>): string {
  return outcome.message.trim() || 'Hosted auth-menu operation failed';
}

function handleHostedAuthMenuOutcome(
  outcome: HostedAuthMenuOutcome,
  refreshLoginState: (walletId?: string) => Promise<void>,
): void {
  switch (outcome.kind) {
    case 'authenticated':
      toast.success(`Logged in as ${outcome.walletId}`, { id: 'login' });
      void refreshLoginState(String(outcome.walletId)).catch(() => {});
      return;
    case 'registered':
      toast.success(`Registration completed: ${outcome.walletId}`, { id: 'registration' });
      void refreshLoginState(String(outcome.walletId)).catch(() => {});
      return;
    case 'account_synced':
      toast.success(`Account synced: ${outcome.walletId}`, { id: 'sync' });
      void refreshLoginState(String(outcome.walletId)).catch(() => {});
      return;
    case 'cancelled':
      toast.info('Wallet authentication cancelled', { id: 'login' });
      return;
    case 'failed':
      console.error('[SeamsAuthMenu]', new Error(outcomeMessage(outcome)));
      toast.error(outcomeMessage(outcome), { id: 'login' });
      return;
    default: {
      const exhaustive: never = outcome;
      throw new Error(`Unknown hosted auth-menu outcome: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function handleHostedAuthMenuOutcomeAndCancelGoogleRequest(
  refreshLoginState: (walletId?: string) => Promise<void>,
  outcome: HostedAuthMenuOutcome,
): void {
  cancelGoogleIdTokenRequest();
  handleHostedAuthMenuOutcome(outcome, refreshLoginState);
}

function providerUnavailableEvidence(message: string): HostedAuthMenuExternalAuthEvidence {
  return { kind: 'failed', code: 'provider_unavailable', message };
}

function providerErrorEvidence(message: string): HostedAuthMenuExternalAuthEvidence {
  return { kind: 'failed', code: 'provider_error', message };
}

function showHostedDemoEmailOtp(delivery: { otpCode: string }): void {
  void showCopiedDemoEmailOtpToast({
    otpCode: delivery.otpCode,
    toastId: 'google-email-otp-code',
    unavailableDescription: 'Email delivery is not configured for this live demo.',
  });
}

function registerGoogleIdTokenRequestCancellation(): () => void {
  return cancelGoogleIdTokenRequest;
}

function syncAuthMenuContainerLock(
  containerRef: React.RefObject<HTMLDivElement | null>,
  lockState: 'idle' | 'cleaning_up',
): void {
  const container = containerRef.current;
  if (container) container.inert = lockState === 'cleaning_up';
}

export function HostedPasskeyLoginMenu(props: HostedPasskeyLoginMenuProps) {
  const authMenuContainerRef = React.useRef<HTMLDivElement>(null);
  React.useEffect(subscribeToHostedAuthMenuErrors.bind(null, authMenuContainerRef), []);
  React.useEffect(registerGoogleIdTokenRequestCancellation, []);
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.relayerUrl || FRONTEND_CONFIG.consoleBaseUrl),
    [],
  );
  const { refreshLoginState, walletLockState } = useSeams();
  React.useEffect(
    syncAuthMenuContainerLock.bind(null, authMenuContainerRef, walletLockState.kind),
    [walletLockState.kind],
  );
  const [googleSsoReadiness, setGoogleSsoReadiness] = React.useState<GoogleSsoReadiness>({
    kind: 'checking',
  });
  React.useEffect(() => {
    let cancelled = false;
    setGoogleSsoReadiness({ kind: 'checking' });
    prepareGoogleSsoReadiness(relayerBaseUrl)
      .then((readiness) => {
        if (!cancelled) setGoogleSsoReadiness(readiness);
      })
      .catch((error: unknown) => {
        if (!cancelled)
          setGoogleSsoReadiness({ kind: 'unavailable', message: formatGoogleBrokerError(error) });
      });
    return () => {
      cancelled = true;
    };
  }, [relayerBaseUrl]);

  const externalAuthBroker = React.useCallback(
    async (
      _request: HostedAuthMenuExternalAuthRequest,
    ): Promise<HostedAuthMenuExternalAuthEvidence> => {
      if (googleSsoReadiness.kind !== 'ready') {
        return providerUnavailableEvidence(
          googleSsoReadiness.kind === 'unavailable'
            ? googleSsoReadiness.message
            : 'Google SSO is still loading. Try again in a moment.',
        );
      }
      try {
        const googleClientId = requirePreparedGoogleSsoClientId(googleSsoReadiness);
        const idToken = await requestGoogleIdToken(googleClientId);
        return { kind: 'google_id_token', idToken };
      } catch (error: unknown) {
        return providerErrorEvidence(formatGoogleBrokerError(error));
      }
    },
    [googleSsoReadiness],
  );

  const resolvedInitialMode = hostedModeFromReactMode(props.defaultModeWhenNoDetectedAccount);

  return (
    <div
      ref={authMenuContainerRef}
      className="passkey-login-container-root"
      aria-busy={walletLockState.kind === 'cleaning_up'}
      data-wallet-lock-state={walletLockState.kind}
    >
      {walletLockState.kind === 'idle' ? (
        <HostedSeamsAuthMenu
          initialMode={resolvedInitialMode}
          registrationAccountInput="implicit_wallet"
          showRegistrationInput={false}
          copy={{
            login: { subtitle: 'Continue with Passkey or Google SSO' },
            register: { subtitle: 'Continue with Passkey or Google SSO' },
          }}
          externalAuthBroker={externalAuthBroker}
          onDemoEmailOtp={showHostedDemoEmailOtp}
          onOutcome={handleHostedAuthMenuOutcomeAndCancelGoogleRequest.bind(
            null,
            refreshLoginState,
          )}
        />
      ) : null}
    </div>
  );
}

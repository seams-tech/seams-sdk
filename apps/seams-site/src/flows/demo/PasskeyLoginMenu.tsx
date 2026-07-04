import {
  useSeams,
  AccountSyncEventPhase,
  AuthMenuMode,
  PasskeyAuthMenu,
  RegistrationEventPhase,
  UnlockEventPhase,
  type EmailOtpAuthPolicy,
  type AccountSyncFlowEvent,
  type PasskeyAuthMenuRegistrationRequest,
  type RegistrationFlowEvent,
  type UnlockFlowEvent,
} from '@seams/sdk/react';
import React from 'react';
import { toast } from 'sonner';

import './PasskeyLoginMenu.css';
import { FRONTEND_CONFIG } from '@/config';
import { useAuthMenuControl } from '@/context/AuthMenuControl';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';

type PasskeyLoginMenuProps = {
  onLoggedIn?: (nearAccountId?: string) => void;
};

type GoogleSsoReadiness =
  | { kind: 'checking' }
  | { kind: 'ready'; clientId: string }
  | { kind: 'unavailable'; message: string };

function normalizeBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

function formatRetryAfter(ms: unknown): string {
  const retryAfterMs = Number(ms);
  if (!Number.isFinite(retryAfterMs) || retryAfterMs <= 0) return '';
  const seconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}

function formatGoogleSsoEmailOtpError(error: unknown): string {
  const code = String((error as any)?.code || '').trim();
  const status = Number((error as any)?.status);
  const message = error instanceof Error ? error.message : String((error as any)?.message || '');
  if (code === 'wallet_id_collision') {
    return 'This Google SSO registration hit an existing wallet id that is not controlled by the new Email OTP signer. Try a fresh dev wallet or use the existing account signer to add this login method.';
  }
  if (code === 'registration_incomplete') {
    return (
      message ||
      'This Google account has an incomplete Email OTP registration. Retry registration after the stale attempt expires, or clear the local dev registration state.'
    );
  }
  if (code === 'stale_identity_mapping') {
    return (
      message ||
      'This Google account has stale Email OTP identity state. Clear the local dev registration state before registering again.'
    );
  }
  if ((code === 'not_found' || status === 404) && /Email OTP enrollment not found/i.test(message)) {
    return 'No Email OTP wallet is enrolled for this Google account yet. Use Register with Google SSO first.';
  }
  if (code === 'rate_limited' || status === 429) {
    const retryAfter = formatRetryAfter((error as any)?.retryAfterMs);
    return retryAfter
      ? `Too many Email OTP requests. Try again in ${retryAfter}.`
      : 'Too many Email OTP requests. Wait a moment and try again.';
  }
  return message ? message : 'Google SSO Email OTP failed. Please retry.';
}

function walletFlowErrorMessage(
  event: { error?: unknown; message?: string },
  fallback: string,
): string {
  const error = event.error as { message?: unknown } | string | undefined;
  if (typeof error === 'string' && error.trim()) return error.trim();
  if (error && typeof error === 'object') {
    const errorMessage = String(error.message || '').trim();
    if (errorMessage) return errorMessage;
  }
  return event.message || fallback;
}

function googleSsoUnavailable(message: string): GoogleSsoReadiness {
  return { kind: 'unavailable', message };
}

function googleSsoReady(clientId: string): GoogleSsoReadiness {
  return { kind: 'ready', clientId };
}

function assertNeverGoogleSsoReadiness(value: never): never {
  throw new Error(`Unknown Google SSO readiness state: ${JSON.stringify(value)}`);
}

async function prepareGoogleSsoReadiness(relayerBaseUrl: string): Promise<GoogleSsoReadiness> {
  if (!relayerBaseUrl) {
    return googleSsoUnavailable('Relayer base URL is not configured');
  }

  const googleOptions = await fetchGoogleAuthOptions(relayerBaseUrl);
  if (!googleOptions.configured || !googleOptions.clientId) {
    return googleSsoUnavailable('Google SSO is not configured on the Router API server');
  }

  await ensureGoogleIdentityScriptLoaded();
  return googleSsoReady(googleOptions.clientId);
}

function requirePreparedGoogleSsoClientId(readiness: GoogleSsoReadiness): string {
  switch (readiness.kind) {
    case 'ready':
      return readiness.clientId;
    case 'checking':
      throw new Error('Google SSO is still loading. Try again in a moment.');
    case 'unavailable':
      throw new Error(readiness.message);
  }
  return assertNeverGoogleSsoReadiness(readiness);
}

function handleRegistrationEvent(event: RegistrationFlowEvent): void {
  if (event.flow !== 'registration') return;
  if (event.phase === RegistrationEventPhase.CANCELLED || event.status === 'cancelled') {
    toast.info(event.message || 'Registration cancelled', { id: 'registration' });
    return;
  }
  if (event.phase === RegistrationEventPhase.FAILED || event.status === 'failed') {
    toast.error(walletFlowErrorMessage(event, 'Registration failed'), { id: 'registration' });
    return;
  }
  if (event.phase === RegistrationEventPhase.STEP_11_COMPLETED && event.status === 'succeeded') {
    toast.success(event.message || 'Registration complete', { id: 'registration' });
    return;
  }
  toast.loading(event.message || 'Processing registration...', { id: 'registration' });
}

function handleUnlockEvent(event: UnlockFlowEvent, loginTarget: string): void {
  if (event.flow !== 'unlock') return;
  if (event.phase === UnlockEventPhase.CANCELLED || event.status === 'cancelled') {
    toast.info(event.message || 'Wallet unlock cancelled', { id: 'login' });
    return;
  }
  if (event.phase === UnlockEventPhase.FAILED || event.status === 'failed') {
    toast.error(walletFlowErrorMessage(event, 'Wallet unlock failed'), { id: 'login' });
    return;
  }
  if (event.phase === UnlockEventPhase.STEP_07_COMPLETED && event.status === 'succeeded') {
    toast.success(`Logged in as ${loginTarget}!`, { id: 'login' });
    return;
  }
  toast.loading(event.message || 'Unlocking wallet...', { id: 'login' });
}

const GOOGLE_EMAIL_OTP_TOAST_ID = 'google-email-otp';

function handleGoogleEmailOtpRegistrationEvent(event: RegistrationFlowEvent): void {
  if (event.flow !== 'registration') return;
  if (event.phase === RegistrationEventPhase.CANCELLED || event.status === 'cancelled') {
    toast.info(event.message || 'Email OTP registration cancelled', {
      id: GOOGLE_EMAIL_OTP_TOAST_ID,
    });
    return;
  }
  if (event.phase === RegistrationEventPhase.FAILED || event.status === 'failed') {
    toast.error(walletFlowErrorMessage(event, 'Email OTP registration failed'), {
      id: GOOGLE_EMAIL_OTP_TOAST_ID,
    });
    return;
  }
  if (event.phase === RegistrationEventPhase.STEP_11_COMPLETED && event.status === 'succeeded') {
    toast.success(event.message || 'Email OTP registration complete', {
      id: GOOGLE_EMAIL_OTP_TOAST_ID,
    });
    return;
  }
  toast.loading(event.message || 'Creating Email OTP wallet...', {
    id: GOOGLE_EMAIL_OTP_TOAST_ID,
  });
}

function handleGoogleEmailOtpUnlockEvent(event: UnlockFlowEvent): void {
  if (event.flow !== 'unlock') return;
  if (event.phase === UnlockEventPhase.CANCELLED || event.status === 'cancelled') {
    toast.info(event.message || 'Email OTP unlock cancelled', { id: GOOGLE_EMAIL_OTP_TOAST_ID });
    return;
  }
  if (event.phase === UnlockEventPhase.FAILED || event.status === 'failed') {
    toast.error(walletFlowErrorMessage(event, 'Email OTP unlock failed'), {
      id: GOOGLE_EMAIL_OTP_TOAST_ID,
    });
    return;
  }
  if (event.phase === UnlockEventPhase.STEP_07_COMPLETED && event.status === 'succeeded') {
    toast.success(event.message || 'Wallet unlocked', { id: GOOGLE_EMAIL_OTP_TOAST_ID });
    return;
  }
  toast.loading(event.message || 'Unlocking wallet...', { id: GOOGLE_EMAIL_OTP_TOAST_ID });
}

function handleGoogleEmailOtpEvent(event: RegistrationFlowEvent | UnlockFlowEvent): void {
  if (event.flow === 'registration') {
    handleGoogleEmailOtpRegistrationEvent(event);
    return;
  }
  handleGoogleEmailOtpUnlockEvent(event);
}

function handleAccountSyncEvent(event: AccountSyncFlowEvent): void {
  if (event.flow !== 'account_sync') return;
  if (event.phase === AccountSyncEventPhase.CANCELLED || event.status === 'cancelled') {
    toast.info(event.message || 'Account sync cancelled', { id: 'sync' });
    return;
  }
  if (event.phase === AccountSyncEventPhase.FAILED || event.status === 'failed') {
    toast.error(walletFlowErrorMessage(event, 'Account sync failed'), { id: 'sync' });
    return;
  }
  if (event.phase === AccountSyncEventPhase.STEP_06_COMPLETED && event.status === 'succeeded') {
    toast.success(event.message || 'Account synced', { id: 'sync' });
    return;
  }
  toast.loading(event.message || 'Syncing account...', { id: 'sync' });
}

export function PasskeyLoginMenu(props: PasskeyLoginMenuProps) {
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.relayerUrl || FRONTEND_CONFIG.consoleBaseUrl),
    [],
  );

  const {
    accountInputState: { targetWalletId, accountExists },
    unlock,
    registerPasskey,
    seams,
    refreshLoginState,
  } = useSeams();

  // let tutorial control the menu (programmatically open/close menus)
  const authMenuControl = useAuthMenuControl();
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
        if (!cancelled) {
          setGoogleSsoReadiness(
            googleSsoUnavailable(error instanceof Error ? error.message : String(error)),
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [relayerBaseUrl]);

  const onRegister = async (request: PasskeyAuthMenuRegistrationRequest) => {
    const result = await registerPasskey({
      wallet: request.wallet,
      onEvent: handleRegistrationEvent,
    });

    if (result.success && result.nearAccountId) {
      const tx = result.transactionId ? ` tx: ${result.transactionId}` : '';
      toast.success(`Registration completed: ${result.walletId}${tx}`, { id: 'registration' });
      props.onLoggedIn?.(result.nearAccountId);
      return result;
    } else {
      throw new Error(result.error || 'Registration failed');
    }
  };

  const loginWithSession = async (walletId: string) => {
    const loginTarget = String(walletId || '').trim();
    if (!loginTarget) {
      throw new Error('Missing walletId for login');
    }

    const result = await unlock(loginTarget, {
      // Mint a JWT session via the Router API server if session.kind is provided
      // session: {
      //   kind: 'jwt',
      // },
      onEvent: (event: UnlockFlowEvent) => handleUnlockEvent(event, loginTarget),
    });
    if (result?.success) {
      const accountId = String(result.nearAccountId || '').trim();
      if (!accountId) {
        throw new Error('Login succeeded but nearAccountId is missing');
      }
      // Surface the minted JWT via toast (truncate to 8 chars)
      if (result.jwt) {
        const short = String(result.jwt).slice(0, 16);
        toast.success(`Session JWT minted: ${short}…`, { id: 'jwt' });
        console.log('[seams-site] JWT returned:', result.jwt);
      }
      props.onLoggedIn?.(accountId);
    }
    return result;
  };

  const onLogin = async () => {
    return await loginWithSession(targetWalletId);
  };

  const onGoogleSsoEmailOtp = async (args: {
    mode: AuthMenuMode;
    emailOtpAuthPolicy: EmailOtpAuthPolicy;
  }) => {
    toast.loading('Opening Google SSO…', { id: 'google-sso' });
    const googleClientId = requirePreparedGoogleSsoClientId(googleSsoReadiness);
    let idToken: string;
    try {
      idToken = await requestGoogleIdToken(googleClientId);
    } catch (error: unknown) {
      const message = formatGoogleSsoEmailOtpError(error);
      toast.error(message, { id: 'google-sso' });
      throw new Error(message);
    }
    const flow = await seams.auth.beginGoogleEmailOtpWalletAuth({
      idToken,
      mode: args.mode === AuthMenuMode.Register ? 'register' : 'login',
      relayUrl: relayerBaseUrl,
      sessionKind: 'jwt',
      emailOtpAuthPolicy: args.emailOtpAuthPolicy,
      onEvent: handleGoogleEmailOtpEvent,
    });
    if (!flow.ok) {
      toast.error(flow.error.message, { id: 'google-sso' });
      throw new Error(flow.error.message);
    }
    toast.success(
      flow.value.mode === 'register'
        ? 'Choose a wallet name to finish registration'
        : 'Email code sent',
      { id: 'google-sso' },
    );
    const onComplete = ({ walletId, mode }: { walletId: string; mode: 'register' | 'login' }) => {
      toast.success(mode === 'register' ? 'Email OTP wallet ready' : 'Wallet unlocked', {
        id: GOOGLE_EMAIL_OTP_TOAST_ID,
      });
      props.onLoggedIn?.(walletId);
    };
    if (flow.value.mode === 'register') {
      return {
        kind: 'registration_flow' as const,
        flow: flow.value,
        onComplete,
      };
    }
    return {
      kind: 'otp_flow' as const,
      flow: flow.value,
      onComplete,
    };
  };

  const onSyncAccount = async () => {
    const result = await seams.recovery.syncAccount({
      ...(targetWalletId ? { walletId: targetWalletId } : {}),
      options: {
        onEvent: handleAccountSyncEvent,
      } as any,
    });

    if (!result?.success) {
      throw new Error(result?.error || result?.message || 'Account sync failed');
    }

    const syncedAccountId = String(result.accountId || '').trim();
    if (!syncedAccountId) {
      throw new Error('Sync succeeded but accountId is missing');
    }

    if (result.loginState?.isLoggedIn) {
      toast.success(`Synced and logged in as ${syncedAccountId}`, { id: 'sync' });
      props.onLoggedIn?.(syncedAccountId);
      return result;
    }

    toast.success(`Synced account ${syncedAccountId}. Logging in...`, { id: 'sync' });
    await loginWithSession(targetWalletId || syncedAccountId);
    return result;
  };

  return (
    <div className="passkey-login-container-root">
      <PasskeyAuthMenu
        // Keep the key stable across accountExists changes to avoid
        // remounting the menu (which causes input focus + content flashes).
        key={`pam2-${authMenuControl.defaultModeOverride ?? 'auto'}-${authMenuControl.remountKey}`}
        defaultMode={
          authMenuControl.defaultModeOverride ??
          (accountExists ? AuthMenuMode.Login : AuthMenuMode.Register)
        }
        showSDKEvents={true}
        loadingScreenDelayMs={100}
        headings={{
          registration: {
            title: 'Register Account',
            subtitle: 'Demo: Create a wallet with Passkey',
          },
        }}
        onLogin={onLogin}
        onRegister={onRegister}
        onSyncAccount={onSyncAccount}
        socialLogin={{
          google: onGoogleSsoEmailOtp,
        }}
      />
    </div>
  );
}

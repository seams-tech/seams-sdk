import {
  useTatchi,
  RegistrationPhase,
  RegistrationStatus,
  LoginPhase,
  SyncAccountPhase,
  SyncAccountStatus,
  AuthMenuMode,
  type RegistrationSSEEvent,
  type SyncAccountSSEEvent,
  PasskeyAuthMenu,
  type EmailOtpAuthPolicy,
} from '@tatchi-xyz/sdk/react';
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

type PasskeyLoginMenuTestOverrides = {
  useTatchiHook?: typeof useTatchi;
  useAuthMenuControlHook?: typeof useAuthMenuControl;
  PasskeyAuthMenuComponent?: typeof PasskeyAuthMenu;
};

type PasskeyLoginMenuProps = {
  onLoggedIn?: (nearAccountId?: string) => void;
  __testOverrides?: PasskeyLoginMenuTestOverrides;
};

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
    return 'This Google account has an incomplete Email OTP registration. Retry registration after the stale attempt expires, or clear the local dev registration state.';
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

export function PasskeyLoginMenu(props: PasskeyLoginMenuProps) {
  const useTatchiHook = props.__testOverrides?.useTatchiHook || useTatchi;
  const useAuthMenuControlHook =
    props.__testOverrides?.useAuthMenuControlHook || useAuthMenuControl;
  const PasskeyAuthMenuComponent =
    props.__testOverrides?.PasskeyAuthMenuComponent || PasskeyAuthMenu;
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.relayerUrl || FRONTEND_CONFIG.consoleBaseUrl),
    [],
  );

  const {
    accountInputState: { targetAccountId, accountExists },
    unlock,
    registerPasskey,
    tatchi,
    refreshLoginState,
  } = useTatchiHook();

  // let tutorial control the menu (programmatically open/close menus)
  const authMenuControl = useAuthMenuControlHook();

  const onRegister = async () => {
    const result = await registerPasskey(targetAccountId, {
      onEvent: (event: RegistrationSSEEvent) => {
        switch (event.phase) {
          case RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION:
            toast.loading('Starting registration...', { id: 'registration' });
            break;
          case RegistrationPhase.STEP_2_KEY_GENERATION:
            if (event.status === RegistrationStatus.SUCCESS) {
              toast.success('Keys generated...', { id: 'registration' });
            }
            break;
          case RegistrationPhase.STEP_3_CONTRACT_PRE_CHECK:
            toast.loading('Checking account availability...', { id: 'registration' });
            break;
          case RegistrationPhase.STEP_4_ACCESS_KEY_ADDITION:
            toast.loading('Creating account...', { id: 'registration' });
            break;
          case RegistrationPhase.STEP_5_CONTRACT_REGISTRATION:
            toast.loading(event.message || 'Creating account and finalizing registration...', {
              id: 'registration',
            });
            break;
          case RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION:
            toast.loading(event.message, { id: 'registration' });
            break;
          case RegistrationPhase.STEP_9_REGISTRATION_COMPLETE:
            if (event.status === RegistrationStatus.SUCCESS) {
              // Final toast with tx hash will be shown after the promise resolves
              toast.success('Registration completed successfully!', { id: 'registration' });
            }
            break;
          case RegistrationPhase.REGISTRATION_ERROR:
            toast.error(event.error || 'Registration failed', { id: 'registration' });
            break;
          default:
            if (event.status === RegistrationStatus.PROGRESS) {
              toast.loading(event.message || 'Processing...', { id: 'registration' });
            }
        }
      },
    });

    if (result.success && result.nearAccountId) {
      const tx = result.transactionId ? ` tx: ${result.transactionId}` : '';
      toast.success(`Registration completed: ${tx}`, { id: 'registration' });
      props.onLoggedIn?.(result.nearAccountId);
      return result;
    } else {
      throw new Error(result.error || 'Registration failed');
    }
  };

  const loginWithSession = async (accountId: string) => {
    const loginTarget = String(accountId || '').trim();
    if (!loginTarget) {
      throw new Error('Missing accountId for login');
    }

    const result = await unlock(loginTarget, {
      // Mint a JWT session via the relay server if session.kind is provided
      // session: {
      //   kind: 'jwt',
      // },
      onEvent: (event) => {
        switch (event.phase) {
          case LoginPhase.STEP_1_PREPARATION:
            toast.loading(`Logging in as ${loginTarget}...`, { id: 'login' });
            break;
          case LoginPhase.STEP_2_WEBAUTHN_ASSERTION:
            toast.loading(event.message, { id: 'login' });
            break;
          case LoginPhase.STEP_3_SESSION_READY:
            toast.loading(event.message || 'Session ready…', { id: 'login' });
            break;
          case LoginPhase.STEP_4_LOGIN_COMPLETE:
            toast.success(`Logged in as ${event.nearAccountId}!`, { id: 'login' });
            break;
          case LoginPhase.LOGIN_ERROR:
            toast.error(event.error, { id: 'login' });
            break;
        }
      },
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
        console.log('[tatchi-site] JWT returned:', result.jwt);
      }
      props.onLoggedIn?.(accountId);
    }
    return result;
  };

  const onLogin = async () => {
    return await loginWithSession(targetAccountId);
  };

  const onGoogleSsoEmailOtp = async (args: {
    mode: AuthMenuMode;
    emailOtpAuthPolicy: EmailOtpAuthPolicy;
  }) => {
    if (!relayerBaseUrl) {
      throw new Error('Relayer base URL is not configured');
    }

    const googleOptions = await fetchGoogleAuthOptions(relayerBaseUrl);
    if (!googleOptions.configured || !googleOptions.clientId) {
      throw new Error('Google SSO is not configured on the relay server');
    }

    toast.loading('Opening Google SSO…', { id: 'google-sso' });
    await ensureGoogleIdentityScriptLoaded();
    let idToken: string;
    try {
      idToken = await requestGoogleIdToken(googleOptions.clientId);
    } catch (error: unknown) {
      const message = formatGoogleSsoEmailOtpError(error);
      toast.error(message, { id: 'google-sso' });
      throw new Error(message);
    }
    const isRegister = args.mode === AuthMenuMode.Register;

    let exchange: Awaited<ReturnType<typeof tatchi.auth.exchangeGoogleEmailOtpSession>>;
    try {
      exchange = await tatchi.auth.exchangeGoogleEmailOtpSession({
        idToken,
        accountMode: isRegister ? 'register' : 'login',
        relayUrl: relayerBaseUrl,
        sessionKind: 'cookie',
      });
    } catch (error: unknown) {
      const formatted = formatGoogleSsoEmailOtpError(error);
      toast.error(formatted, { id: 'google-sso' });
      throw new Error(formatted);
    }

    const walletId = String(exchange.session?.walletId || exchange.session?.userId || '').trim();
    if (!walletId) {
      throw new Error('Google session exchange did not return a wallet id');
    }
    const emailHint = String(exchange.session?.email || '').trim();
    const displayHint = emailHint || walletId;

    const googleResolution = exchange.session.googleEmailOtpResolution;
    const otpFlow: 'enroll' | 'login' =
      googleResolution?.mode === 'register_started' ? 'enroll' : 'login';
    if (isRegister && otpFlow === 'login') {
      toast.info('Existing Email OTP wallet found for this Google account. Sending a login code instead.', {
        id: 'google-sso',
      });
    } else if (otpFlow === 'enroll') {
      toast.info('Creating a new Email OTP wallet for this Google account. Sending the setup code now.', {
        id: 'google-sso',
      });
    }
    const challenge = await (async () => {
      try {
        if (otpFlow === 'login') {
          return await tatchi.auth.requestEmailOtpChallenge({
            nearAccountId: walletId,
            relayUrl: relayerBaseUrl,
          });
        }

        return await tatchi.auth.requestEmailOtpEnrollmentChallenge({
          nearAccountId: walletId,
          relayUrl: relayerBaseUrl,
        });
      } catch (error: unknown) {
        const message = formatGoogleSsoEmailOtpError(error);
        toast.error(message, { id: 'google-sso' });
        throw new Error(message);
      }
    })();

    toast.success('Email code sent', { id: 'google-sso' });

    return {
      username: walletId,
      otpPrompt: {
        title: 'Check your email to unlock your wallet',
        description: `Enter the 6-digit code we sent${emailHint ? ` to ${emailHint}` : ''}.`,
        emailHint: displayHint,
        submitLabel: 'Unlock wallet',
        helperText:
          'Google keeps you signed in. The email code unlocks wallet signing for this session.',
        onSubmit: async (otpCode: string) => {
          const toastId = 'google-email-otp';
          toast.loading('Unlocking wallet with email code…', { id: toastId });
          if (otpFlow === 'enroll') {
            await tatchi.auth.enrollAndLoginWithEmailOtpEcdsaCapability({
              nearAccountId: walletId,
              chain: 'tempo',
              challengeId: challenge.challengeId,
              otpCode,
              relayUrl: relayerBaseUrl,
              sessionKind: 'cookie',
              emailOtpAuthPolicy: args.emailOtpAuthPolicy,
              ...(googleResolution?.registrationAttemptId
                ? { registrationAttemptId: googleResolution.registrationAttemptId }
                : {}),
              ...(exchange.session.runtimePolicyScope
                ? { runtimePolicyScope: exchange.session.runtimePolicyScope }
                : {}),
            });
          } else {
            await tatchi.auth.loginWithEmailOtpEcdsaCapability({
              nearAccountId: walletId,
              chain: 'tempo',
              challengeId: challenge.challengeId,
              otpCode,
              relayUrl: relayerBaseUrl,
              sessionKind: 'cookie',
              emailOtpAuthPolicy: args.emailOtpAuthPolicy,
              ...(exchange.session.runtimePolicyScope
                ? { runtimePolicyScope: exchange.session.runtimePolicyScope }
                : {}),
            });
          }
          await refreshLoginState(walletId);
          const session = await tatchi.auth.getWalletSession(walletId);
          if (!session.login.isLoggedIn) {
            throw new Error('Wallet unlocked, but the local signing session is not ready yet.');
          }
          toast.success(`Wallet unlocked${emailHint ? ` for ${emailHint}` : ''}`, { id: toastId });
          props.onLoggedIn?.(walletId);
        },
      },
    };
  };

  const onSyncAccount = async () => {
    const result = await tatchi.recovery.syncAccount({
      ...(targetAccountId ? { accountId: targetAccountId } : {}),
      options: {
        onEvent: (event: SyncAccountSSEEvent) => {
          switch (event.phase) {
            case SyncAccountPhase.STEP_1_PREPARATION:
              toast.loading(event.message || 'Preparing account sync…', { id: 'sync' });
              break;
            case SyncAccountPhase.STEP_2_WEBAUTHN_AUTHENTICATION:
              toast.loading(event.message || 'Authenticating with passkey…', { id: 'sync' });
              break;
            case SyncAccountPhase.STEP_4_AUTHENTICATOR_SAVED:
              if (event.status === SyncAccountStatus.SUCCESS) {
                toast.success(event.message || 'Passkey saved locally', { id: 'sync' });
              }
              break;
            case SyncAccountPhase.STEP_5_SYNC_ACCOUNT_COMPLETE:
              if (event.status === SyncAccountStatus.SUCCESS) {
                toast.success(event.message || 'Account synced', { id: 'sync' });
              }
              break;
            case SyncAccountPhase.ERROR:
              toast.error((event as any)?.error || event.message || 'Account sync failed', {
                id: 'sync',
              });
              break;
            default:
              break;
          }
        },
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
    await loginWithSession(syncedAccountId);
    return result;
  };

  return (
    <div className="passkey-login-container-root">
      <PasskeyAuthMenuComponent
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

import {
  useSeams,
  AccountSyncEventPhase,
  AuthMenuMode,
  PasskeyAuthMenu,
  RegistrationEventPhase,
  UnlockEventPhase,
  type EmailOtpAuthPolicy,
  type AccountSyncFlowEvent,
  type RegistrationFlowEvent,
  type UnlockFlowEvent,
} from '@seams/sdk/react';
import { toWalletSubjectId, walletSessionRefFromSession } from '@seams/sdk';
import React from 'react';
import { toast } from 'sonner';

import './PasskeyLoginMenu.css';
import { FRONTEND_CONFIG } from '@/config';
import { useAuthMenuControl } from '@/context/AuthMenuControl';
import { resolveDemoThresholdEcdsaChainTarget } from './demoChainTargets';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';

type PasskeyLoginMenuTestOverrides = {
  useSeamsHook?: typeof useSeams;
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
  const useSeamsHook = props.__testOverrides?.useSeamsHook || useSeams;
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
    seams,
    refreshLoginState,
  } = useSeamsHook();

  // let tutorial control the menu (programmatically open/close menus)
  const authMenuControl = useAuthMenuControlHook();

  const onRegister = async () => {
    const result = await registerPasskey(targetAccountId, {
      onEvent: handleRegistrationEvent,
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
      onEvent: (event) => handleUnlockEvent(event, loginTarget),
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

    let exchange: Awaited<ReturnType<typeof seams.auth.exchangeGoogleEmailOtpSession>>;
    try {
      exchange = await seams.auth.exchangeGoogleEmailOtpSession({
        idToken,
        accountMode: isRegister ? 'register' : 'login',
        relayUrl: relayerBaseUrl,
        sessionKind: 'jwt',
        onEvent: handleGoogleEmailOtpEvent,
      });
    } catch (error: unknown) {
      const formatted = formatGoogleSsoEmailOtpError(error);
      toast.error(formatted, { id: 'google-sso' });
      throw new Error(formatted);
    }

    let walletId = String(exchange.session?.walletId || exchange.session?.userId || '').trim();
    if (!walletId) {
      throw new Error('Google session exchange did not return a wallet id');
    }
    const emailHint = String(exchange.session?.email || '').trim();
    let appSessionJwt = String(exchange.jwt || '').trim();
    if (!appSessionJwt) {
      throw new Error('Google SSO did not return an app session token for Email OTP wallet access');
    }
    let googleResolution = exchange.session.googleEmailOtpResolution;
    let otpFlow: 'enroll' | 'login' =
      googleResolution?.mode === 'register_started' ? 'enroll' : 'login';
    if (isRegister && otpFlow === 'login') {
      toast.info(
        'Existing Email OTP wallet found for this Google account. Sending a login code instead.',
        {
          id: 'google-sso',
        },
      );
    } else if (otpFlow === 'enroll') {
      toast.info(
        'Creating a new Email OTP wallet for this Google account. Sending the setup code now.',
        {
          id: 'google-sso',
        },
      );
    }
    const requestCurrentOtpChallenge = async () => {
      try {
        if (otpFlow === 'login') {
          return await seams.auth.requestEmailOtpChallenge({
            nearAccountId: walletId,
            relayUrl: relayerBaseUrl,
            appSessionJwt,
            onEvent: handleGoogleEmailOtpUnlockEvent,
          });
        }

        return await seams.auth.requestEmailOtpEnrollmentChallenge({
          nearAccountId: walletId,
          relayUrl: relayerBaseUrl,
          appSessionJwt,
          onEvent: handleGoogleEmailOtpRegistrationEvent,
        });
      } catch (error: unknown) {
        const message = formatGoogleSsoEmailOtpError(error);
        toast.error(message, { id: 'google-sso' });
        throw new Error(message);
      }
    };
    const buildOtpPromptCopy = () => ({
      title:
        otpFlow === 'enroll'
          ? 'Check your email to finish registration'
          : 'Check your email to unlock your wallet',
      description:
        otpFlow === 'enroll'
          ? `Enter the 6-digit setup code we sent${emailHint ? ` to ${emailHint}` : ''}.`
          : `Enter the 6-digit code we sent${emailHint ? ` to ${emailHint}` : ''}.`,
      submitLabel: otpFlow === 'enroll' ? 'Create wallet' : 'Unlock wallet',
      helperText:
        otpFlow === 'enroll'
          ? 'Google started your wallet registration. The email code secures wallet signing for this account.'
          : 'Google keeps you signed in. The email code unlocks wallet signing for this session.',
    });
    let challenge = await requestCurrentOtpChallenge();
    const otpPromptCopy = buildOtpPromptCopy();

    toast.success('Email code sent', { id: 'google-sso' });

    return {
      username: walletId,
      otpPrompt: {
        title: otpPromptCopy.title,
        description: otpPromptCopy.description,
        emailHint: emailHint || walletId,
        accountId: walletId,
        submitLabel: otpPromptCopy.submitLabel,
        helperText: otpPromptCopy.helperText,
        ...(isRegister
          ? {
              onRerollAccount: async () => {
                toast.loading('Generating another wallet name...', { id: 'google-sso' });
                const nextExchange = await seams.auth.exchangeGoogleEmailOtpSession({
                  idToken,
                  accountMode: 'register',
                  relayUrl: relayerBaseUrl,
                  sessionKind: 'jwt',
                  rerollRegistrationAttempt: true,
                  onEvent: handleGoogleEmailOtpEvent,
                });
                const nextWalletId = String(
                  nextExchange.session?.walletId || nextExchange.session?.userId || '',
                ).trim();
                const nextAppSessionJwt = String(nextExchange.jwt || '').trim();
                if (!nextWalletId || !nextAppSessionJwt) {
                  throw new Error('Google SSO did not return a new wallet name');
                }
                walletId = nextWalletId;
                appSessionJwt = nextAppSessionJwt;
                googleResolution = nextExchange.session.googleEmailOtpResolution;
                otpFlow =
                  googleResolution?.mode === 'register_started' ? 'enroll' : 'login';
                challenge = await requestCurrentOtpChallenge();
                toast.success('New wallet name selected. Email code sent.', { id: 'google-sso' });
                const nextPromptCopy = buildOtpPromptCopy();
                return {
                  username: walletId,
                  accountId: walletId,
                  emailHint: emailHint || walletId,
                  title: nextPromptCopy.title,
                  description: nextPromptCopy.description,
                  submitLabel: nextPromptCopy.submitLabel,
                  helperText: nextPromptCopy.helperText,
                };
              },
            }
          : {}),
        onResend: async () => {
          challenge = await requestCurrentOtpChallenge();
          toast.success('Email code sent', { id: 'google-email-otp-resend' });
          return {
            challengeId: challenge.challengeId,
            ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
          };
        },
        onSubmit: async (otpCode: string) => {
          const toastId = GOOGLE_EMAIL_OTP_TOAST_ID;
          toast.loading(
            otpFlow === 'enroll'
              ? 'Creating Email OTP wallet with setup code...'
              : 'Unlocking wallet with email code...',
            { id: toastId },
          );
          if (otpFlow === 'enroll') {
            await seams.auth.enrollAndLoginWithEmailOtpEcdsaCapability({
              walletSession: walletSessionRefFromSession({
                walletId,
                userId: exchange.session.userId,
              }),
              subjectId: toWalletSubjectId(walletId),
              chainTarget: resolveDemoThresholdEcdsaChainTarget('tempo'),
              challengeId: challenge.challengeId,
              otpCode,
              relayUrl: relayerBaseUrl,
              appSessionJwt,
              ...(exchange.session.runtimePolicyScope
                ? { runtimePolicyScope: exchange.session.runtimePolicyScope }
                : {}),
              emailOtpAuthPolicy: args.emailOtpAuthPolicy,
              onEvent: handleGoogleEmailOtpEvent,
              ...(googleResolution?.registrationAttemptId
                ? { registrationAttemptId: googleResolution.registrationAttemptId }
                : {}),
            });
          } else {
            await seams.auth.loginWithEmailOtpEcdsaCapability({
              walletSession: walletSessionRefFromSession({
                walletId,
                userId: exchange.session.userId,
              }),
              subjectId: toWalletSubjectId(walletId),
              chainTarget: resolveDemoThresholdEcdsaChainTarget('tempo'),
              challengeId: challenge.challengeId,
              otpCode,
              relayUrl: relayerBaseUrl,
              appSessionJwt,
              ...(exchange.session.runtimePolicyScope
                ? { runtimePolicyScope: exchange.session.runtimePolicyScope }
                : {}),
              emailOtpAuthPolicy: args.emailOtpAuthPolicy,
              onEvent: handleGoogleEmailOtpUnlockEvent,
            });
          }
          await refreshLoginState(walletId);
          const session = await seams.auth.getWalletSession(walletId);
          if (!session.login.isLoggedIn) {
            throw new Error('Wallet unlocked, but the local signing session is not ready yet.');
          }
          toast.success(
            otpFlow === 'enroll'
              ? `Email OTP wallet ready${emailHint ? ` for ${emailHint}` : ''}`
              : `Wallet unlocked${emailHint ? ` for ${emailHint}` : ''}`,
            { id: toastId },
          );
          props.onLoggedIn?.(walletId);
        },
      },
    };
  };

  const onSyncAccount = async () => {
    const result = await seams.recovery.syncAccount({
      ...(targetAccountId ? { accountId: targetAccountId } : {}),
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

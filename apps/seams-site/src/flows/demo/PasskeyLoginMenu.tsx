import {
  useSeams,
  AccountSyncEventPhase,
  AuthMenuMode,
  SeamsAuthMenu,
  RegistrationEventPhase,
  UnlockEventPhase,
  type AccountSyncFlowEvent,
  type DemoEmailOtpCodeResponse,
  type SeamsAuthMenuPasskeyLoginRequest,
  type SeamsAuthMenuRegistrationRequest,
  type SeamsAuthMenuSocialLoginArgs,
  type SeamsAuthMenuSyncAccountRequest,
  type RegistrationFlowEvent,
  type UnlockFlowEvent,
} from '@seams/sdk/react';
import React from 'react';
import { toast } from 'sonner';

import './PasskeyLoginMenu.css';
import { FRONTEND_CONFIG } from '@/config';
import { useAuthMenuControl } from '@/context/AuthMenuControl';
import { demoPasskeyEcdsaSignerOptions } from './demoPasskeyEcdsaSignerOptions';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';

type PasskeyLoginMenuProps = {
  onLoggedIn?: (nearAccountId?: string) => void;
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
};

type GoogleSsoReadiness =
  | { kind: 'checking' }
  | { kind: 'ready'; clientId: string }
  | { kind: 'unavailable'; message: string };

type ExistingAccountDetection =
  | { kind: 'checking' }
  | { kind: 'detected_existing_account' }
  | { kind: 'no_existing_account_detected' };

function normalizeBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasNonEmptyArray(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0;
}

function recentUnlocksContainExistingAccount(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    hasNonEmptyArray(value.walletIds) ||
    hasNonEmptyArray(value.accountIds) ||
    hasNonEmptyArray(value.accounts) ||
    isRecord(value.lastUsedAccount)
  );
}

function resolveDetectedAccountDefaultMode(input: {
  controlOverride?: AuthMenuMode;
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
  detection: ExistingAccountDetection;
}): AuthMenuMode | undefined {
  if (input.controlOverride !== undefined) return input.controlOverride;
  if (input.defaultModeWhenNoDetectedAccount === undefined) return undefined;

  switch (input.detection.kind) {
    case 'checking':
    case 'detected_existing_account':
      return undefined;
    case 'no_existing_account_detected':
      return input.defaultModeWhenNoDetectedAccount;
  }

  const exhaustive: never = input.detection;
  throw new Error(`Unknown existing-account detection state: ${JSON.stringify(exhaustive)}`);
}

function shouldDelayAuthMenuForAccountDetection(input: {
  controlOverride?: AuthMenuMode;
  defaultModeWhenNoDetectedAccount?: AuthMenuMode;
  detection: ExistingAccountDetection;
}): boolean {
  return (
    input.controlOverride === undefined &&
    input.defaultModeWhenNoDetectedAccount !== undefined &&
    input.detection.kind === 'checking'
  );
}

function assertDemoPasskeyRegistrationProvisionedEcdsa(result: {
  success?: boolean;
  thresholdEcdsaEthereumAddress?: string | null;
}): void {
  if (!result.success) return;
  const thresholdOwnerAddress = String(result.thresholdEcdsaEthereumAddress || '').trim();
  if (thresholdOwnerAddress) return;
  throw new Error(
    'Registration completed without threshold ECDSA signer; this demo requires Tempo and EVM threshold signers.',
  );
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
    return 'No Email OTP wallet is enrolled for this Google account yet. Use Sign up with Google SSO first.';
  }
  if (code === 'rate_limited' || status === 429) {
    const retryAfter = formatRetryAfter((error as any)?.retryAfterMs);
    return retryAfter
      ? `Too many Email OTP requests. Try again in ${retryAfter}.`
      : 'Too many Email OTP requests. Wait a moment and try again.';
  }
  return message ? message : 'Google SSO Email OTP failed. Please retry.';
}

function isGoogleAccountRegistrationRequired(error: unknown): boolean {
  if (!error || typeof error !== 'object' || !('code' in error)) return false;
  return (error as { code?: unknown }).code === 'google_account_registration_required';
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

function messageFromUnknown(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) return error.message.trim();
  const message = String((error as { message?: unknown })?.message || '').trim();
  return message || fallback;
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

export function showDemoEmailOtpToast(response: DemoEmailOtpCodeResponse): void {
  toast.success(`Demo email code: ${response.otpCode}`, {
    id: GOOGLE_EMAIL_OTP_TOAST_ID,
  });
}

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

  const { unlock, registerPasskey, seams, refreshLoginState } = useSeams();

  // let tutorial control the menu (programmatically open/close menus)
  const authMenuControl = useAuthMenuControl();
  const [googleSsoReadiness, setGoogleSsoReadiness] = React.useState<GoogleSsoReadiness>({
    kind: 'checking',
  });
  const [existingAccountDetection, setExistingAccountDetection] =
    React.useState<ExistingAccountDetection>({
      kind:
        props.defaultModeWhenNoDetectedAccount === undefined
          ? 'detected_existing_account'
          : 'checking',
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

  React.useEffect(() => {
    if (props.defaultModeWhenNoDetectedAccount === undefined) {
      setExistingAccountDetection({ kind: 'detected_existing_account' });
      return;
    }

    let cancelled = false;
    setExistingAccountDetection({ kind: 'checking' });
    seams.auth
      .getRecentUnlocks()
      .then((recentUnlocks: unknown) => {
        if (cancelled) return;
        setExistingAccountDetection(
          recentUnlocksContainExistingAccount(recentUnlocks)
            ? { kind: 'detected_existing_account' }
            : { kind: 'no_existing_account_detected' },
        );
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        console.warn('[seams-site] Existing demo account detection failed:', error);
        setExistingAccountDetection({ kind: 'no_existing_account_detected' });
      });

    return () => {
      cancelled = true;
    };
  }, [props.defaultModeWhenNoDetectedAccount, seams]);

  const onRegister = async (request: SeamsAuthMenuRegistrationRequest) => {
    const result = await registerPasskey({
      wallet: request.wallet,
      signerOptions: demoPasskeyEcdsaSignerOptions(
        seams.configs.signing.thresholdEcdsa.provisioningDefaults,
      ),
      onEvent: handleRegistrationEvent,
    });
    assertDemoPasskeyRegistrationProvisionedEcdsa(result);

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
      // The wallet and Gateway are cross-origin, so warm-up authorization must use a bearer JWT.
      session: {
        kind: 'jwt',
        exchange: { type: 'passkey_assertion' },
      },
      onEvent: (event: UnlockFlowEvent) => handleUnlockEvent(event, loginTarget),
    });
    if (result?.success) {
      const accountId = String(result.nearAccountId || '').trim();
      if (!accountId) {
        throw new Error('Login succeeded but nearAccountId is missing');
      }
      props.onLoggedIn?.(accountId);
    }
    return result;
  };

  const onLogin = async (request: SeamsAuthMenuPasskeyLoginRequest) => {
    return await loginWithSession(request.walletId);
  };

  const onGoogleSsoEmailOtp = async (args: SeamsAuthMenuSocialLoginArgs) => {
    toast.loading('Opening Google SSO…', { id: GOOGLE_EMAIL_OTP_TOAST_ID });
    try {
      const googleClientId = requirePreparedGoogleSsoClientId(googleSsoReadiness);
      const idToken = await requestGoogleIdToken(googleClientId);
      const flow = await seams.auth.beginGoogleEmailOtpWalletAuth({
        idToken,
        mode: args.mode === AuthMenuMode.Register ? 'register' : 'login',
        relayUrl: relayerBaseUrl,
        sessionKind: 'jwt',
        emailOtpAuthPolicy: args.emailOtpAuthPolicy,
        onDemoOtp: showDemoEmailOtpToast,
        onEvent: handleGoogleEmailOtpEvent,
      });
      if (!flow.ok) {
        throw flow.error;
      }
      if (flow.value.mode === 'register') {
        toast.success('Choose a wallet name to finish registration', {
          id: GOOGLE_EMAIL_OTP_TOAST_ID,
        });
      } else if (flow.value.delivery.kind === 'provider') {
        toast.success('Email code sent', { id: GOOGLE_EMAIL_OTP_TOAST_ID });
      }
      const onComplete = async ({
        walletId,
        mode,
      }: {
        walletId: string;
        mode: 'register' | 'login';
      }) => {
        await refreshLoginState(walletId);
        /* TEMP-DIAG: splits "host session says logged out" from "react
           provider state didn't update" for the email-OTP unlock bug */
        try {
          const session = await seams.auth.getWalletSession(walletId);
          console.debug('[demo][email-otp] post-unlock session', {
            walletId,
            mode,
            isLoggedIn: session.login.isLoggedIn,
            sessionWalletId: session.login.walletId,
            currentAuthMethod: session.currentAuthMethod?.kind,
          });
        } catch (err) {
          console.debug('[demo][email-otp] post-unlock getWalletSession FAILED', err);
        }
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
    } catch (error: unknown) {
      const message = formatGoogleSsoEmailOtpError(error);
      toast.error(message, { id: GOOGLE_EMAIL_OTP_TOAST_ID });
      if (isGoogleAccountRegistrationRequired(error)) {
        return {
          kind: 'registration_required' as const,
          reason: 'google_account_not_registered' as const,
        };
      }
      throw new Error(message);
    }
  };

  const onSyncAccount = async (request: SeamsAuthMenuSyncAccountRequest) => {
    try {
      const result = await seams.recovery.syncAccount({
        walletId: request.walletId,
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
      await loginWithSession(request.walletId || syncedAccountId);
      return result;
    } catch (error: unknown) {
      const message = messageFromUnknown(error, 'Account sync failed');
      console.warn('[seams-site] Account sync failed:', error);
      toast.error(message, { id: 'sync' });
      throw new Error(message);
    }
  };

  const resolvedDefaultMode = resolveDetectedAccountDefaultMode({
    controlOverride: authMenuControl.defaultModeOverride,
    defaultModeWhenNoDetectedAccount: props.defaultModeWhenNoDetectedAccount,
    detection: existingAccountDetection,
  });
  const delayAuthMenu = shouldDelayAuthMenuForAccountDetection({
    controlOverride: authMenuControl.defaultModeOverride,
    defaultModeWhenNoDetectedAccount: props.defaultModeWhenNoDetectedAccount,
    detection: existingAccountDetection,
  });

  if (delayAuthMenu) {
    return (
      <div className="passkey-login-container-root">
        <div className="passkey-login-menu-placeholder" aria-hidden="true" />
      </div>
    );
  }

  return (
    <div className="passkey-login-container-root">
      <SeamsAuthMenu
        // Keep the key stable across account state changes to avoid
        // remounting the menu during login-state refreshes.
        key={`seams-auth-menu-${resolvedDefaultMode ?? 'auto'}-${authMenuControl.remountKey}`}
        defaultMode={resolvedDefaultMode}
        loadingScreenDelayMs={100}
        headings={{
          login: {
            title: 'Sign in',
            subtitle: 'Continue with Passkey or Google SSO',
          },
          registration: {
            title: 'Create your account',
            subtitle: 'Continue with Passkey or Google SSO',
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

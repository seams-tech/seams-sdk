import React from 'react';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { StoredAccountOption } from '@/react/types';
import {
  EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH,
  EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH,
  formatEmailOtpRecoveryKey,
  normalizeEmailOtpRecoveryKey,
} from '@shared/utils/emailOtpRecoveryKey';
import type { PasskeyAuthMenuRuntime } from '../adapters/seams';
import { AuthMenuMode, type PasskeyAuthMenuOtpPrompt, type PasskeyAuthMenuProps } from '../types';
import type { SocialLoginHandlers } from '../ui/SocialProviders';
import { usePasskeyAuthMenuForceInitialRegister } from '../hydrationContext';
import { useAuthMenuMode } from './mode';
import { getProceedEligibility } from './proceedEligibility';

export interface PasskeyAuthMenuLinkDeviceController {
  isOpen: boolean;
  onClose: () => void;
  onEvent: (event: LinkDeviceFlowEvent) => void;
  onError: (error: Error) => void;
}

export interface PasskeyAuthMenuOtpPromptController {
  title: string;
  description: string;
  emailHint?: string;
  accountId?: string;
  submitLabel: string;
  helperText: string;
  code: string;
  recoveryKey: string;
  recoveryKeyRequired: boolean;
  recoveryKeyLabel: string;
  recoveryKeyPlaceholder: string;
  recoveryKeyHelperText: string;
  recoveryKeyScanLabel?: string;
  recoveryKeyScanBusy: boolean;
  recoveryKeyReady: boolean;
  submitting: boolean;
  error?: string;
  rerollAccountLabel?: string;
  rerollAccountDisabled: boolean;
  onRerollAccount?: () => void;
  resendLabel?: string;
  resendDisabled: boolean;
  onResend?: () => void;
  onCodeChange: (value: string) => void;
  onRecoveryKeyChange: (value: string) => void;
  onRecoveryKeyScan?: () => void;
  onSubmit: () => void;
  onBack: () => void;
}

export interface PasskeyAuthMenuController {
  mode: AuthMenuMode;
  title: { title: string; subtitle: string };
  waiting: boolean;
  waitingReason: 'passkey' | 'social' | 'sync' | null;
  showScanDevice: boolean;
  otpPrompt: PasskeyAuthMenuOtpPromptController | null;
  methodError?: string;
  currentValue: string;
  passkeyAccountOptions: StoredAccountOption[];
  postfixText?: string;
  isUsingExistingAccount?: boolean;
  secure: boolean;
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
  canShowContinue: boolean;
  canSubmit: boolean;
  onSegmentChange: (next: AuthMenuMode) => void;
  onInputChange: (val: string) => void;
  onProceed: () => void;
  onResetToStart: () => void;
  openScanDevice: () => void;
  onSocialLogin: (provider: keyof SocialLoginHandlers, modeOverride?: AuthMenuMode) => void;
  closeLinkDeviceView: (reason: 'user' | 'flow') => void;
  linkDevice: PasskeyAuthMenuLinkDeviceController;
}

type ActiveOtpPromptState = {
  username?: string;
  title: string;
  description: string;
  emailHint?: string;
  accountId?: string;
  submitLabel: string;
  helperText: string;
  recoveryKey?: {
    required: boolean;
    label: string;
    placeholder: string;
    helperText: string;
    scanLabel?: string;
    onScan?: () => string | void | Promise<string | void>;
  };
  onSubmit: PasskeyAuthMenuOtpPrompt['onSubmit'];
  onRerollAccount?: PasskeyAuthMenuOtpPrompt['onRerollAccount'];
  onResend?: PasskeyAuthMenuOtpPrompt['onResend'];
  resendDebounceMs: number;
};

function resolveOtpPrompt(
  prompt: PasskeyAuthMenuOtpPrompt,
  username?: string,
): ActiveOtpPromptState {
  const title = String(prompt.title || '').trim() || 'Check your email to unlock your wallet';
  const description =
    String(prompt.description || '').trim() || 'Enter the 6-digit code we sent to continue.';
  const emailHint = String(prompt.emailHint || '').trim();
  const accountId = String(prompt.accountId || username || '').trim();
  const submitLabel = String(prompt.submitLabel || '').trim() || 'Unlock wallet';
  const helperText =
    String(prompt.helperText || '').trim() ||
    'Google keeps you signed in. This code unlocks wallet signing.';
  const recoveryKeyPrompt = prompt.recoveryKey;
  const scanLabel = String(recoveryKeyPrompt?.scanLabel || '').trim();
  return {
    ...(username ? { username } : {}),
    title,
    description,
    ...(emailHint ? { emailHint } : {}),
    ...(accountId ? { accountId } : {}),
    submitLabel,
    helperText,
    ...(recoveryKeyPrompt
      ? {
          recoveryKey: {
            required: recoveryKeyPrompt.required !== false,
            label: String(recoveryKeyPrompt.label || '').trim() || 'Recovery key',
            placeholder:
              String(recoveryKeyPrompt.placeholder || '').trim() ||
              'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',
            helperText:
              String(recoveryKeyPrompt.helperText || '').trim() ||
              'Enter one unused 8-group recovery key from account setup.',
            ...(scanLabel ? { scanLabel } : {}),
            ...(recoveryKeyPrompt.onScan ? { onScan: recoveryKeyPrompt.onScan } : {}),
          },
        }
      : {}),
    onSubmit: prompt.onSubmit,
    ...(prompt.onRerollAccount ? { onRerollAccount: prompt.onRerollAccount } : {}),
    ...(prompt.onResend ? { onResend: prompt.onResend } : {}),
    resendDebounceMs: Math.max(1000, Math.floor(Number(prompt.resendDebounceMs) || 10_000)),
  };
}

function formatPartialRecoveryKeyInput(input: string): string {
  const normalized = String(input || '')
    .replace(/[\s-]/g, '')
    .toUpperCase()
    .slice(0, EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH);
  const groups: string[] = [];
  for (let index = 0; index < normalized.length; index += EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH) {
    groups.push(normalized.slice(index, index + EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH));
  }
  return groups.join('-');
}

function isRecoveryKeyReady(input: string): boolean {
  try {
    normalizeEmailOtpRecoveryKey(input);
    return true;
  } catch {
    return false;
  }
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function formatEmailOtpResendError(error: unknown): string {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '')
      : '';
  const retryAfterMs =
    error && typeof error === 'object' && 'retryAfterMs' in error
      ? Number((error as { retryAfterMs?: unknown }).retryAfterMs)
      : NaN;
  if (code === 'rate_limited') {
    if (Number.isFinite(retryAfterMs) && retryAfterMs > 0) {
      return `Too many requests. Try again in ${Math.max(1, Math.ceil(retryAfterMs / 1000))}s.`;
    }
    return 'Too many requests. Try again shortly.';
  }
  return getErrorMessage(error, 'Could not send code. Try again.');
}

export function usePasskeyAuthMenuController(
  props: Pick<
    PasskeyAuthMenuProps,
    | 'onLogin'
    | 'onRegister'
    | 'onSyncAccount'
    | 'emailOtpAuthPolicy'
    | 'defaultMode'
    | 'headings'
    | 'linkDeviceOptions'
    | 'socialLogin'
  >,
  runtime: PasskeyAuthMenuRuntime,
): PasskeyAuthMenuController {
  const secure = typeof window !== 'undefined' ? window.isSecureContext : true;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy = props.emailOtpAuthPolicy || 'session';
  const currentValue = runtime.inputUsername;
  const setCurrentValue = runtime.setInputUsername;
  const forceInitialRegister = usePasskeyAuthMenuForceInitialRegister();

  const {
    mode,
    setMode,
    title,
    onSegmentChange: onSegmentChangeBase,
    onInputChange: onInputChangeBase,
    resetToDefault,
  } = useAuthMenuMode({
    defaultMode: props.defaultMode,
    accountExists: runtime.accountExists,
    currentValue,
    setCurrentValue,
    headings: props.headings,
    forceInitialRegister,
  });

  const latestValueRef = React.useRef<string>(currentValue);
  React.useEffect(() => {
    latestValueRef.current = currentValue;
  }, [currentValue]);

  // Recent-login prefill state (from lazy feature island).
  const prefilledFromRecentRef = React.useRef(false);
  const prefilledValueRef = React.useRef<string>('');
  const prevModeRef = React.useRef<AuthMenuMode | null>(null);
  const lastUserSelectedModeRef = React.useRef<AuthMenuMode | null>(null);

  const [waiting, setWaiting] = React.useState(false);
  const [waitingReason, setWaitingReason] = React.useState<'passkey' | 'social' | 'sync' | null>(
    null,
  );
  const [showScanDevice, setShowScanDevice] = React.useState(false);
  const [otpPromptState, setOtpPromptState] = React.useState<ActiveOtpPromptState | null>(null);
  const [otpCode, setOtpCode] = React.useState('');
  const [otpRecoveryKey, setOtpRecoveryKey] = React.useState('');
  const [otpSubmitting, setOtpSubmitting] = React.useState(false);
  const [otpError, setOtpError] = React.useState<string>('');
  const [otpRerollBusy, setOtpRerollBusy] = React.useState(false);
  const [otpRecoveryKeyScanBusy, setOtpRecoveryKeyScanBusy] = React.useState(false);
  const [otpResendBusy, setOtpResendBusy] = React.useState(false);
  const [otpResendUntilMs, setOtpResendUntilMs] = React.useState(0);
  const [otpResendStatus, setOtpResendStatus] = React.useState('');
  const [otpResendNowMs, setOtpResendNowMs] = React.useState(() => Date.now());
  const [methodError, setMethodError] = React.useState<string>('');

  React.useEffect(() => {
    if (!otpPromptState || !otpResendUntilMs) return;
    if (Date.now() >= otpResendUntilMs) {
      setOtpResendNowMs(Date.now());
      return;
    }
    const timer = window.setInterval(() => setOtpResendNowMs(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [otpPromptState, otpResendUntilMs]);

  const clearPrefillMarkers = React.useCallback(() => {
    prefilledFromRecentRef.current = false;
    prefilledValueRef.current = '';
  }, []);

  const onSegmentChange = React.useCallback(
    (next: AuthMenuMode) => {
      lastUserSelectedModeRef.current = next;
      if (mode === AuthMenuMode.Login && next !== AuthMenuMode.Login) {
        if (prefilledFromRecentRef.current && currentValue === prefilledValueRef.current) {
          setCurrentValue('');
        }
        clearPrefillMarkers();
      }
      setMethodError('');
      onSegmentChangeBase(next);
    },
    [mode, currentValue, setCurrentValue, onSegmentChangeBase, clearPrefillMarkers],
  );

  const onInputChange = React.useCallback(
    (val: string) => {
      if (val !== prefilledValueRef.current) {
        prefilledFromRecentRef.current = false;
      }
      if (methodError) setMethodError('');
      onInputChangeBase(val);
    },
    [methodError, onInputChangeBase],
  );

  const { canShowContinue, canSubmit } = getProceedEligibility({
    mode,
    currentValue,
    accountExists: runtime.accountExists,
    secure,
  });

  const passkeyAccountOptions = React.useMemo(
    () => {
      const byAccountId = new Map<string, StoredAccountOption>();
      for (const option of runtime.accountOptions ?? []) {
        const nearAccountId = String(option.nearAccountId || '').trim();
        if (!nearAccountId) continue;
        const authMethodKey = option.authMethod || 'passkey';
        byAccountId.set(`${nearAccountId}:${authMethodKey}`, {
          nearAccountId,
          ...(typeof option.signerSlot === 'number' ? { signerSlot: option.signerSlot } : {}),
          ...(option.authMethod ? { authMethod: option.authMethod } : {}),
        });
      }
      return [...byAccountId.values()].sort((a, b) =>
        a.nearAccountId.localeCompare(b.nearAccountId),
      );
    },
    [runtime.accountOptions],
  );

  // If the user is attempting to register but we discover the account already exists,
  // automatically switch them to the Login tab.
  React.useEffect(() => {
    if (waiting) return;
    if (mode !== AuthMenuMode.Register) return;
    if (!runtime.accountExists) return;
    if (lastUserSelectedModeRef.current === AuthMenuMode.Register) return;
    setMode(AuthMenuMode.Login);
  }, [mode, runtime.accountExists, setMode, waiting]);

  // Lazy feature-island: entering Login can prefill the last used account username.
  React.useEffect(() => {
    const prevMode = prevModeRef.current;
    prevModeRef.current = mode;

    const enteringLogin = mode === AuthMenuMode.Login && prevMode !== AuthMenuMode.Login;
    if (!enteringLogin) return;
    if (latestValueRef.current.trim().length > 0) return;

    let cancelled = false;
    void import('../features/recentUnlockPrefill')
      .then(async (m) => {
        const result = await m.getRecentUnlockPrefill(runtime.seamsWeb);
        if (cancelled || !result?.username) return;
        if (prevModeRef.current !== AuthMenuMode.Login) return;
        if (latestValueRef.current.trim().length > 0) return;

        setCurrentValue(result.username);
        prefilledFromRecentRef.current = true;
        prefilledValueRef.current = result.username;
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [mode, runtime.seamsWeb, setCurrentValue]);

  const fallbackOnEvent = React.useCallback((event: LinkDeviceFlowEvent) => {
    console.log('ShowQRCode event:', event);
  }, []);

  const fallbackOnError = React.useCallback((error: Error) => {
    console.error('ShowQRCode error:', error);
  }, []);

  const handleLinkDeviceEvent = props.linkDeviceOptions?.onEvent ?? fallbackOnEvent;
  const handleLinkDeviceError = props.linkDeviceOptions?.onError ?? fallbackOnError;
  const handleLinkDeviceCancelled = props.linkDeviceOptions?.onCancelled;

  const stopLinkDeviceFlow = React.useCallback(() => {
    const stopper = runtime.stopDevice2LinkingFlow;
    if (!stopper) return;
    void stopper().catch(() => {});
  }, [runtime.stopDevice2LinkingFlow]);

  const closeLinkDeviceView = React.useCallback(
    (reason: 'user' | 'flow') => {
      stopLinkDeviceFlow();
      setShowScanDevice(false);
      if (reason === 'user') {
        handleLinkDeviceCancelled?.();
      }
    },
    [stopLinkDeviceFlow, handleLinkDeviceCancelled],
  );

  const onResetToStart = React.useCallback(() => {
    setWaiting(false);
    setWaitingReason(null);
    setOtpPromptState(null);
    setOtpCode('');
    setOtpRecoveryKey('');
    setOtpError('');
    setMethodError('');
    setOtpSubmitting(false);
    setOtpRerollBusy(false);
    setOtpRecoveryKeyScanBusy(false);
    setOtpResendBusy(false);
    setOtpResendUntilMs(0);
    setOtpResendStatus('');
    if (showScanDevice) {
      closeLinkDeviceView('user');
    } else {
      setShowScanDevice(false);
    }
    lastUserSelectedModeRef.current = null;
    resetToDefault();
    setCurrentValue('');
    clearPrefillMarkers();
  }, [showScanDevice, closeLinkDeviceView, resetToDefault, setCurrentValue, clearPrefillMarkers]);

  const onProceed = React.useCallback(() => {
    if (!canSubmit) {
      if (mode === AuthMenuMode.Register) {
        if (!secure) {
          setMethodError('Passkey registration requires HTTPS or localhost.');
        } else if (runtime.accountExists) {
          setMethodError('This account already exists. Log in instead.');
        } else if (currentValue.trim().length === 0) {
          setMethodError('Pick a username to create a passkey account.');
        }
      }
      return;
    }

    setWaiting(true);
    setWaitingReason(mode === AuthMenuMode.Sync ? 'sync' : 'passkey');

    void (async () => {
      try {
        if (mode === AuthMenuMode.Sync) {
          await props.onSyncAccount?.();
          setWaiting(false);
          setWaitingReason(null);
          setMode(AuthMenuMode.Login);
        } else if (mode === AuthMenuMode.Login) {
          await props.onLogin?.();
          setWaiting(false);
          setWaitingReason(null);
          closeLinkDeviceView('flow');
          setMode(AuthMenuMode.Login);
        } else {
          await props.onRegister?.();
          setWaiting(false);
          setWaitingReason(null);
          setMode(AuthMenuMode.Login);
        }
      } catch {
        if (mode === AuthMenuMode.Login) {
          setWaiting(false);
          setWaitingReason(null);
          closeLinkDeviceView('flow');
          setMode(mode);
          return;
        }
        onResetToStart();
      }
    })();
  }, [
    canSubmit,
    mode,
    secure,
    runtime.accountExists,
    currentValue,
    props.onSyncAccount,
    props.onLogin,
    props.onRegister,
    setMode,
    closeLinkDeviceView,
    onResetToStart,
  ]);

  const openScanDevice = React.useCallback(() => {
    setShowScanDevice(true);
  }, []);

  const onSocialLogin = React.useCallback(
    (provider: keyof SocialLoginHandlers, modeOverride?: AuthMenuMode) => {
      if (waiting) return;
      const handler = props.socialLogin?.[provider];
      if (typeof handler !== 'function') return;
      const socialMode = modeOverride ?? mode;
      setWaiting(true);
      setWaitingReason('social');
      setOtpError('');
      setMethodError('');
      void (async () => {
        try {
          const result = await handler({ mode: socialMode, emailOtpAuthPolicy });
          const flowResult = result && typeof result === 'object' ? result : null;
          const username = String(flowResult?.username || '').trim();
          if (username) {
            setCurrentValue(username);
          }
          if (flowResult?.otpPrompt) {
            setOtpCode('');
            setOtpRecoveryKey('');
            setOtpError('');
            setOtpRerollBusy(false);
            setOtpRecoveryKeyScanBusy(false);
            setOtpResendBusy(false);
            setOtpResendUntilMs(0);
            setOtpResendStatus('');
            setMethodError('');
            setOtpPromptState(resolveOtpPrompt(flowResult.otpPrompt, username || undefined));
          } else if (username) {
            await runtime.refreshLoginState(username).catch(() => {});
          }
        } catch (error: unknown) {
          setMethodError(getErrorMessage(error, 'Google SSO failed. Please retry.'));
        } finally {
          setWaiting(false);
          setWaitingReason(null);
        }
      })();
    },
    [waiting, props.socialLogin, mode, emailOtpAuthPolicy, runtime, setCurrentValue],
  );

  const onOtpCodeChange = React.useCallback(
    (value: string) => {
      const normalized = String(value || '')
        .replace(/\D/g, '')
        .slice(0, 6);
      setOtpCode(normalized);
      if (otpError) setOtpError('');
    },
    [otpError],
  );

  const onOtpRecoveryKeyChange = React.useCallback(
    (value: string) => {
      setOtpRecoveryKey(formatPartialRecoveryKeyInput(value));
      if (otpError) setOtpError('');
    },
    [otpError],
  );

  const onOtpPromptBack = React.useCallback(() => {
    setOtpPromptState(null);
    setOtpCode('');
    setOtpRecoveryKey('');
    setOtpError('');
    setOtpSubmitting(false);
    setOtpRerollBusy(false);
    setOtpRecoveryKeyScanBusy(false);
    setOtpResendBusy(false);
    setOtpResendUntilMs(0);
    setOtpResendStatus('');
  }, []);

  const onOtpResend = React.useCallback(() => {
    const activePrompt = otpPromptState;
    if (!activePrompt?.onResend || otpSubmitting || otpRerollBusy || otpResendBusy) return;
    const now = Date.now();
    if (otpResendUntilMs && now < otpResendUntilMs) return;
    setOtpResendBusy(true);
    setOtpResendStatus('');
    setOtpResendUntilMs(now + activePrompt.resendDebounceMs);
    setOtpResendNowMs(now);
    void (async () => {
      try {
        const result = await activePrompt.onResend?.();
        const emailHint = String(result?.emailHint || '').trim();
        if (emailHint) {
          setOtpPromptState((current) => (current ? { ...current, emailHint } : current));
        }
        setOtpResendStatus('Code sent');
      } catch (error: unknown) {
        setOtpResendStatus('');
        setOtpError(formatEmailOtpResendError(error));
      } finally {
        setOtpResendBusy(false);
      }
    })();
  }, [otpPromptState, otpSubmitting, otpRerollBusy, otpResendBusy, otpResendUntilMs]);

  const onOtpRecoveryKeyScan = React.useCallback(() => {
    const activePrompt = otpPromptState;
    if (!activePrompt?.recoveryKey?.onScan || otpSubmitting || otpRecoveryKeyScanBusy) return;
    setOtpRecoveryKeyScanBusy(true);
    setOtpError('');
    void (async () => {
      try {
        const result = await activePrompt.recoveryKey?.onScan?.();
        const value = String(result || '').trim();
        if (value) setOtpRecoveryKey(formatPartialRecoveryKeyInput(value));
      } catch (error: unknown) {
        setOtpError(getErrorMessage(error, 'Could not scan recovery key. Enter it manually.'));
      } finally {
        setOtpRecoveryKeyScanBusy(false);
      }
    })();
  }, [otpPromptState, otpSubmitting, otpRecoveryKeyScanBusy]);

  const onOtpRerollAccount = React.useCallback(() => {
    const activePrompt = otpPromptState;
    if (!activePrompt?.onRerollAccount || otpSubmitting || otpRerollBusy || otpResendBusy) return;
    setOtpRerollBusy(true);
    setOtpCode('');
    setOtpRecoveryKey('');
    setOtpError('');
    setOtpResendStatus('');
    void (async () => {
      try {
        const result = await activePrompt.onRerollAccount?.();
        const username = String(result?.username || result?.accountId || '').trim();
        const accountId = String(result?.accountId || result?.username || '').trim();
        const emailHint = String(result?.emailHint || '').trim();
        const title = String(result?.title || '').trim();
        const description = String(result?.description || '').trim();
        const submitLabel = String(result?.submitLabel || '').trim();
        const helperText = String(result?.helperText || '').trim();
        const codeDelivery =
          result && typeof result === 'object' && result.codeDelivery === 'reused'
            ? 'reused'
            : 'sent';
        if (username) setCurrentValue(username);
        setOtpPromptState((current) =>
          current
            ? {
                ...current,
                ...(username ? { username } : {}),
                ...(accountId ? { accountId } : {}),
                ...(emailHint ? { emailHint } : {}),
                ...(title ? { title } : {}),
                ...(description ? { description } : {}),
                ...(submitLabel ? { submitLabel } : {}),
                ...(helperText ? { helperText } : {}),
              }
            : current,
        );
        setOtpResendStatus(
          codeDelivery === 'reused' ? 'Use the email code already sent' : 'Code sent',
        );
      } catch (error: unknown) {
        setOtpError(getErrorMessage(error, 'Could not choose another wallet name. Try again.'));
      } finally {
        setOtpRerollBusy(false);
      }
    })();
  }, [otpPromptState, otpSubmitting, otpRerollBusy, otpResendBusy, setCurrentValue]);

  const onOtpSubmit = React.useCallback(() => {
    const activePrompt = otpPromptState;
    if (!activePrompt || otpSubmitting) return;
    if (!/^\d{6}$/.test(otpCode)) {
      setOtpError('Enter the 6-digit code from your email.');
      return;
    }
    let recoveryKey: string | undefined;
    if (activePrompt.recoveryKey?.required) {
      try {
        recoveryKey = formatEmailOtpRecoveryKey(normalizeEmailOtpRecoveryKey(otpRecoveryKey));
      } catch (error: unknown) {
        setOtpError(getErrorMessage(error, 'Enter a valid 8-group recovery key.'));
        return;
      }
    }
    setOtpSubmitting(true);
    setOtpError('');
    void (async () => {
      try {
        await activePrompt.onSubmit(otpCode, recoveryKey ? { recoveryKey } : undefined);
        const username = String(activePrompt.username || '').trim();
        if (username) {
          await runtime.refreshLoginState(username).catch(() => {});
        }
        setOtpPromptState(null);
        setOtpCode('');
        setOtpRecoveryKey('');
      } catch (error: unknown) {
        const message =
          error instanceof Error && error.message
            ? error.message
            : 'Email code verification failed.';
        setOtpError(message);
      } finally {
        setOtpSubmitting(false);
      }
    })();
  }, [otpCode, otpPromptState, otpRecoveryKey, otpSubmitting, runtime]);

  const otpPrompt: PasskeyAuthMenuOtpPromptController | null = React.useMemo(() => {
    if (!otpPromptState) return null;
    const resendSeconds =
      otpResendUntilMs > otpResendNowMs
        ? Math.max(1, Math.ceil((otpResendUntilMs - otpResendNowMs) / 1000))
        : 0;
    const canResend = typeof otpPromptState.onResend === 'function';
    const canRerollAccount = typeof otpPromptState.onRerollAccount === 'function';
    const recoveryKeyRequired = otpPromptState.recoveryKey?.required === true;
    const recoveryKeyReady = recoveryKeyRequired ? isRecoveryKeyReady(otpRecoveryKey) : true;
    const canScanRecoveryKey = typeof otpPromptState.recoveryKey?.onScan === 'function';
    return {
      title: otpPromptState.title,
      description: otpPromptState.description,
      ...(otpPromptState.emailHint ? { emailHint: otpPromptState.emailHint } : {}),
      ...(otpPromptState.accountId ? { accountId: otpPromptState.accountId } : {}),
      submitLabel: otpPromptState.submitLabel,
      helperText: otpPromptState.helperText,
      code: otpCode,
      recoveryKey: otpRecoveryKey,
      recoveryKeyRequired,
      recoveryKeyLabel: otpPromptState.recoveryKey?.label || 'Recovery key',
      recoveryKeyPlaceholder:
        otpPromptState.recoveryKey?.placeholder || 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',
      recoveryKeyHelperText:
        otpPromptState.recoveryKey?.helperText ||
        'Enter one unused 8-group recovery key from account setup.',
      recoveryKeyScanBusy: otpRecoveryKeyScanBusy,
      recoveryKeyReady,
      ...(canScanRecoveryKey
        ? {
            recoveryKeyScanLabel: otpRecoveryKeyScanBusy
              ? 'Scanning…'
              : otpPromptState.recoveryKey?.scanLabel || 'Scan recovery key',
            onRecoveryKeyScan: onOtpRecoveryKeyScan,
          }
        : {}),
      submitting: otpSubmitting,
      ...(otpError ? { error: otpError } : {}),
      rerollAccountDisabled: !canRerollAccount || otpSubmitting || otpRerollBusy || otpResendBusy,
      ...(canRerollAccount
        ? {
            rerollAccountLabel: otpRerollBusy
              ? 'Generating another name...'
              : 'Generate another name',
            onRerollAccount: onOtpRerollAccount,
          }
        : {}),
      resendDisabled:
        !canResend || otpSubmitting || otpRerollBusy || otpResendBusy || resendSeconds > 0,
      ...(canResend
        ? {
            resendLabel: otpResendBusy
              ? 'Sending…'
              : otpResendStatus && resendSeconds > 0
                ? otpResendStatus
                : 'Resend Code',
            onResend: onOtpResend,
          }
        : {}),
      onCodeChange: onOtpCodeChange,
      onRecoveryKeyChange: onOtpRecoveryKeyChange,
      onSubmit: onOtpSubmit,
      onBack: onOtpPromptBack,
    };
  }, [
    otpPromptState,
    otpCode,
    otpRecoveryKey,
    otpSubmitting,
    otpError,
    otpRerollBusy,
    otpRecoveryKeyScanBusy,
    otpResendBusy,
    otpResendUntilMs,
    otpResendNowMs,
    otpResendStatus,
    onOtpCodeChange,
    onOtpRecoveryKeyChange,
    onOtpRecoveryKeyScan,
    onOtpRerollAccount,
    onOtpResend,
    onOtpSubmit,
    onOtpPromptBack,
  ]);

  const linkDevice: PasskeyAuthMenuLinkDeviceController = React.useMemo(
    () => ({
      isOpen: showScanDevice,
      onClose: () => closeLinkDeviceView('flow'),
      onEvent: handleLinkDeviceEvent,
      onError: handleLinkDeviceError,
    }),
    [showScanDevice, closeLinkDeviceView, handleLinkDeviceEvent, handleLinkDeviceError],
  );

  return {
    mode,
    title,
    waiting,
    waitingReason,
    showScanDevice,
    otpPrompt,
    ...(methodError ? { methodError } : {}),
    currentValue,
    passkeyAccountOptions,
    postfixText: runtime.displayPostfix,
    isUsingExistingAccount: runtime.isUsingExistingAccount,
    secure,
    emailOtpAuthPolicy,
    canShowContinue,
    canSubmit,
    onSegmentChange,
    onInputChange,
    onProceed,
    onResetToStart,
    openScanDevice,
    onSocialLogin,
    closeLinkDeviceView,
    linkDevice,
  };
}

export default usePasskeyAuthMenuController;

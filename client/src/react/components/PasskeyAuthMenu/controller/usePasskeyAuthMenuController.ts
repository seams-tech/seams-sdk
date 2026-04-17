import React from 'react';
import type { DeviceLinkingSSEEvent } from '@/core/types/sdkSentEvents';
import type { EmailOtpAuthPolicy } from '@/core/types/tatchi';
import type { PasskeyAuthMenuRuntime } from '../adapters/tatchi';
import { AuthMenuMode, type PasskeyAuthMenuOtpPrompt, type PasskeyAuthMenuProps } from '../types';
import type { SocialLoginHandlers } from '../ui/SocialProviders';
import { usePasskeyAuthMenuForceInitialRegister } from '../hydrationContext';
import { useAuthMenuMode } from './mode';
import { getProceedEligibility } from './proceedEligibility';

export interface PasskeyAuthMenuLinkDeviceController {
  isOpen: boolean;
  onClose: () => void;
  onEvent: (event: DeviceLinkingSSEEvent) => void;
  onError: (error: Error) => void;
}

export interface PasskeyAuthMenuOtpPromptController {
  title: string;
  description: string;
  emailHint?: string;
  submitLabel: string;
  helperText: string;
  code: string;
  submitting: boolean;
  error?: string;
  onCodeChange: (value: string) => void;
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
  submitLabel: string;
  helperText: string;
  onSubmit: PasskeyAuthMenuOtpPrompt['onSubmit'];
};

function resolveOtpPrompt(
  prompt: PasskeyAuthMenuOtpPrompt,
  username?: string,
): ActiveOtpPromptState {
  const title = String(prompt.title || '').trim() || 'Check your email to unlock your wallet';
  const description =
    String(prompt.description || '').trim() || 'Enter the 6-digit code we sent to continue.';
  const emailHint = String(prompt.emailHint || '').trim();
  const submitLabel = String(prompt.submitLabel || '').trim() || 'Unlock wallet';
  const helperText =
    String(prompt.helperText || '').trim() ||
    'Google keeps you signed in. This code unlocks wallet signing.';
  return {
    ...(username ? { username } : {}),
    title,
    description,
    ...(emailHint ? { emailHint } : {}),
    submitLabel,
    helperText,
    onSubmit: prompt.onSubmit,
  };
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
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
  const [otpSubmitting, setOtpSubmitting] = React.useState(false);
  const [otpError, setOtpError] = React.useState<string>('');
  const [methodError, setMethodError] = React.useState<string>('');

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
        const result = await m.getRecentUnlockPrefill(runtime.tatchiPasskey);
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
  }, [mode, runtime.tatchiPasskey, setCurrentValue]);

  const fallbackOnEvent = React.useCallback((event: DeviceLinkingSSEEvent) => {
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
    setOtpError('');
    setMethodError('');
    setOtpSubmitting(false);
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
    if (!canSubmit) return;

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
            setOtpError('');
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

  const onOtpPromptBack = React.useCallback(() => {
    setOtpPromptState(null);
    setOtpCode('');
    setOtpError('');
    setOtpSubmitting(false);
  }, []);

  const onOtpSubmit = React.useCallback(() => {
    const activePrompt = otpPromptState;
    if (!activePrompt || otpSubmitting) return;
    if (!/^\d{6}$/.test(otpCode)) {
      setOtpError('Enter the 6-digit code from your email.');
      return;
    }
    setOtpSubmitting(true);
    setOtpError('');
    void (async () => {
      try {
        await activePrompt.onSubmit(otpCode);
        const username = String(activePrompt.username || '').trim();
        if (username) {
          await runtime.refreshLoginState(username).catch(() => {});
        }
        setOtpPromptState(null);
        setOtpCode('');
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
  }, [otpCode, otpPromptState, otpSubmitting, runtime]);

  const otpPrompt: PasskeyAuthMenuOtpPromptController | null = React.useMemo(() => {
    if (!otpPromptState) return null;
    return {
      title: otpPromptState.title,
      description: otpPromptState.description,
      ...(otpPromptState.emailHint ? { emailHint: otpPromptState.emailHint } : {}),
      submitLabel: otpPromptState.submitLabel,
      helperText: otpPromptState.helperText,
      code: otpCode,
      submitting: otpSubmitting,
      ...(otpError ? { error: otpError } : {}),
      onCodeChange: onOtpCodeChange,
      onSubmit: onOtpSubmit,
      onBack: onOtpPromptBack,
    };
  }, [
    otpPromptState,
    otpCode,
    otpSubmitting,
    otpError,
    onOtpCodeChange,
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

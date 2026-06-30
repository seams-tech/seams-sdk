import React from 'react';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { StoredAccountOption } from '@/react/types';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH,
  EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH,
  formatEmailOtpRecoveryKey,
  normalizeEmailOtpRecoveryKey,
} from '@shared/utils/emailOtpRecoveryKey';
import type { PasskeyAuthMenuRuntime } from '../adapters/seams';
import {
  AuthMenuMode,
  type PasskeyAuthMenuOtpPrompt,
  type PasskeyAuthMenuProps,
  type PasskeyAuthMenuRegistrationAccountInput,
  type PasskeyAuthMenuRegistrationPrompt,
  type PasskeyAuthMenuRegistrationRequest,
  type PasskeyAuthMenuSocialCompletion,
} from '../types';
import type {
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthLoginFlow,
  GoogleEmailOtpWalletAuthRegistrationFlow,
} from '@/SeamsWeb';
import type { RegistrationActivationSurfaceState } from '@/SeamsWeb/publicApi/types';
import type { SocialLoginHandlers } from '../ui/SocialProviders';
import { usePasskeyAuthMenuForceInitialRegister } from '../hydrationContext';
import { useAuthMenuMode } from './mode';
import { getProceedEligibility } from './proceedEligibility';
import { extractUsernameFromAccountId } from '@/react/hooks/useAccountInput';
import {
  createReadableWalletId,
  type RegisterWalletInput,
  walletIdFromString,
} from '@shared/utils/registrationIntent';

type ProvidedRegistrationWalletInput = Extract<RegisterWalletInput, { kind: 'provided' }>;

type PasskeyRegistrationDraft = {
  kind: 'passkey_registration_draft';
  wallet: ProvidedRegistrationWalletInput;
};

function createPasskeyRegistrationDraft(): PasskeyRegistrationDraft {
  return {
    kind: 'passkey_registration_draft',
    wallet: {
      kind: 'provided',
      walletId: createReadableWalletId(),
    },
  };
}

function passkeyRegistrationDraftWalletId(draft: PasskeyRegistrationDraft): string {
  return String(draft.wallet.walletId);
}

function providedRegistrationWalletFromValue(walletId: string): ProvidedRegistrationWalletInput {
  return {
    kind: 'provided',
    walletId: walletIdFromString(walletId),
  };
}

function createPasskeyAuthMenuRegistrationRequest(input: {
  registrationAccountInput: PasskeyAuthMenuRegistrationAccountInput;
  passkeyRegistrationDraft: PasskeyRegistrationDraft;
  currentValue: string;
}): PasskeyAuthMenuRegistrationRequest {
  switch (input.registrationAccountInput) {
    case 'implicit_wallet':
      return {
        kind: 'implicit_wallet',
        wallet: input.passkeyRegistrationDraft.wallet,
      };
    case 'sponsored_named_near_account':
      return {
        kind: 'sponsored_named_near_account',
        wallet: providedRegistrationWalletFromValue(input.currentValue.trim()),
      };
  }
  const exhaustive: never = input.registrationAccountInput;
  throw new Error(`Unknown passkey registration account input: ${exhaustive}`);
}

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

export interface PasskeyAuthMenuRegistrationPromptController {
  title: string;
  description: string;
  emailHint?: string;
  accountId: string;
  submitLabel: string;
  helperText: string;
  submitting: boolean;
  error?: string;
  rerollAccountLabel: string;
  rerollAccountDisabled: boolean;
  onRerollAccount: () => void;
  onSubmit: () => void;
  onBack: () => void;
}

export interface PasskeyAuthMenuPostRecoveryRotationPromptController {
  walletId: string;
  activeRecoveryCodeCount: number;
  expectedRecoveryCodeCount: number;
  rotating: boolean;
  error?: string;
  onRotate: () => void;
  onDismiss: () => void;
}

export interface PasskeyAuthMenuController {
  mode: AuthMenuMode;
  title: { title: string; subtitle: string };
  waiting: boolean;
  waitingReason: 'passkey' | 'social' | 'restore' | null;
  showScanDevice: boolean;
  otpPrompt: PasskeyAuthMenuOtpPromptController | null;
  registrationPrompt: PasskeyAuthMenuRegistrationPromptController | null;
  postRecoveryRotationPrompt: PasskeyAuthMenuPostRecoveryRotationPromptController | null;
  methodError?: string;
  currentValue: string;
  showAccountInput: boolean;
  accountInputReadOnly: boolean;
  accountInputRerollLabel?: string;
  accountInputRerollDisabled: boolean;
  registrationActivationWallet?: ProvidedRegistrationWalletInput;
  onAccountInputReroll?: () => void;
  targetExists: boolean;
  passkeyAccountOptions: StoredAccountOption[];
  postfixText?: string;
  isUsingExistingAccount?: boolean;
  secure: boolean;
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
  canShowContinue: boolean;
  canSubmit: boolean;
  canRecoverAccountWithEmail: boolean;
  onSegmentChange: (next: AuthMenuMode) => void;
  onInputChange: (val: string) => void;
  onProceed: () => void;
  onRecoverAccountWithEmail: () => void;
  onResetToStart: () => void;
  openScanDevice: () => void;
  onSocialLogin: (provider: keyof SocialLoginHandlers, modeOverride?: AuthMenuMode) => void;
  onRegistrationActivationSurfaceStateChange: (state: RegistrationActivationSurfaceState) => void;
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
  onCancel?: PasskeyAuthMenuOtpPrompt['onCancel'];
  resendDebounceMs: number;
  refreshLoginStateAfterSubmit: boolean;
};

type ActiveRegistrationPromptState = {
  username: string;
  title: string;
  description: string;
  emailHint?: string;
  accountId: string;
  submitLabel: string;
  helperText: string;
  onSubmit: PasskeyAuthMenuRegistrationPrompt['onSubmit'];
  onRerollAccount: NonNullable<PasskeyAuthMenuRegistrationPrompt['onRerollAccount']>;
  onCancel?: PasskeyAuthMenuRegistrationPrompt['onCancel'];
};

type ActivePostRecoveryRotationPromptState = {
  kind: 'post_recovery_rotation_prompt';
  walletId: string;
  activeRecoveryCodeCount: number;
  expectedRecoveryCodeCount: number;
};

function resolveOtpPrompt(
  prompt: PasskeyAuthMenuOtpPrompt,
  username?: string,
  options?: { refreshLoginStateAfterSubmit?: boolean },
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
    ...(prompt.onCancel ? { onCancel: prompt.onCancel } : {}),
    resendDebounceMs: Math.max(1000, Math.floor(Number(prompt.resendDebounceMs) || 10_000)),
    refreshLoginStateAfterSubmit: options?.refreshLoginStateAfterSubmit !== false,
  };
}

function resolveRegistrationPrompt(
  prompt: PasskeyAuthMenuRegistrationPrompt,
): ActiveRegistrationPromptState {
  const accountId = String(prompt.accountId || prompt.username || '').trim();
  if (!accountId) {
    throw new Error('Registration prompt requires an account id');
  }
  const title = String(prompt.title || '').trim() || 'Create your Email OTP wallet';
  const description =
    String(prompt.description || '').trim() || 'Google verified your email address.';
  const emailHint = String(prompt.emailHint || '').trim();
  const submitLabel = String(prompt.submitLabel || '').trim() || 'Create wallet';
  const helperText =
    String(prompt.helperText || '').trim() ||
    'Choose this wallet name or generate another one before creating the wallet.';
  const onRerollAccount = prompt.onRerollAccount;
  if (!onRerollAccount) {
    throw new Error('Registration prompt requires wallet name reroll');
  }
  return {
    username: accountId,
    accountId,
    title,
    description,
    ...(emailHint ? { emailHint } : {}),
    submitLabel,
    helperText,
    onSubmit: prompt.onSubmit,
    onRerollAccount,
    ...(prompt.onCancel ? { onCancel: prompt.onCancel } : {}),
  };
}

function otpPromptFromGoogleEmailOtpFlow(input: {
  flow: GoogleEmailOtpWalletAuthFlow;
  onComplete?: PasskeyAuthMenuSocialCompletion;
}): { username: string; otpPrompt: PasskeyAuthMenuOtpPrompt } {
  if (input.flow.mode !== 'login') {
    throw new Error('Google Email OTP registration must use a registration prompt.');
  }
  let activeFlow: GoogleEmailOtpWalletAuthLoginFlow = input.flow;
  const promptForFlow = (): PasskeyAuthMenuOtpPrompt => ({
    title: activeFlow.prompt.title,
    description: activeFlow.prompt.description,
    emailHint: activeFlow.emailHint,
    accountId: activeFlow.walletId,
    submitLabel: activeFlow.prompt.submitLabel,
    helperText: activeFlow.prompt.helperText,
    onResend: async () => {
      const result = await activeFlow.resend();
      if (!result.ok) throw new Error(result.error.message);
      if (result.value.mode !== 'login') {
        throw new Error('Google Email OTP resend returned a registration flow.');
      }
      activeFlow = result.value;
      return { emailHint: activeFlow.emailHint };
    },
    onSubmit: async (otpCode: string) => {
      const result = await activeFlow.submit({ otpCode });
      if (!result.ok) throw new Error(result.error.message);
      await input.onComplete?.(result.value);
    },
    onCancel: async () => {
      await activeFlow.cancel();
    },
  });
  return {
    username: activeFlow.walletId,
    otpPrompt: promptForFlow(),
  };
}

function registrationPromptFromGoogleEmailOtpFlow(input: {
  flow: GoogleEmailOtpWalletAuthRegistrationFlow;
  onComplete?: PasskeyAuthMenuSocialCompletion;
}): { username: string; registrationPrompt: PasskeyAuthMenuRegistrationPrompt } {
  let activeFlow = input.flow;
  const promptForFlow = (): PasskeyAuthMenuRegistrationPrompt => ({
    title: activeFlow.prompt.title,
    description: activeFlow.prompt.description,
    emailHint: activeFlow.emailHint,
    accountId: activeFlow.walletId,
    username: activeFlow.walletId,
    submitLabel: activeFlow.prompt.submitLabel,
    helperText: activeFlow.prompt.helperText,
    onRerollAccount: async () => {
      const result = await activeFlow.rerollWalletId();
      if (!result.ok) throw new Error(result.error.message);
      if (result.value.mode !== 'register') {
        throw new Error('Google SSO resolved an existing wallet. Use the unlock flow.');
      }
      activeFlow = result.value;
      return {
        username: activeFlow.walletId,
        accountId: activeFlow.walletId,
        emailHint: activeFlow.emailHint,
        title: activeFlow.prompt.title,
        description: activeFlow.prompt.description,
        submitLabel: activeFlow.prompt.submitLabel,
        helperText: activeFlow.prompt.helperText,
      };
    },
    onSubmit: async () => {
      const result = await activeFlow.completeRegistration();
      if (!result.ok) throw new Error(result.error.message);
      await input.onComplete?.(result.value);
    },
    onCancel: async () => {
      await activeFlow.cancel();
    },
  });
  return {
    username: activeFlow.walletId,
    registrationPrompt: promptForFlow(),
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

function postRecoveryRotationPromptFromSubmitResult(input: {
  result: unknown;
  fallbackWalletId: string;
}): ActivePostRecoveryRotationPromptState | null {
  const obj =
    input.result && typeof input.result === 'object' && !Array.isArray(input.result)
      ? (input.result as Record<string, unknown>)
      : null;
  if (!obj) return null;
  const activeRecoveryCodeCount = Number(obj.activeRecoveryWrappedEnrollmentEscrowCount);
  if (
    !Number.isFinite(activeRecoveryCodeCount) ||
    activeRecoveryCodeCount >= EMAIL_OTP_RECOVERY_KEY_COUNT
  ) {
    return null;
  }
  const walletId = String(obj.walletId || input.fallbackWalletId || '').trim();
  if (!walletId) return null;
  return {
    kind: 'post_recovery_rotation_prompt',
    walletId,
    activeRecoveryCodeCount: Math.max(0, Math.floor(activeRecoveryCodeCount)),
    expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
  };
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function assertNeverRegistrationActivationSurfaceState(state: never): never {
  throw new Error(`Unhandled registration activation surface state: ${JSON.stringify(state)}`);
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

function normalizeStoredAccountId(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function isLocalPasskeyAccountOption(option: StoredAccountOption): boolean {
  return option.authMethod !== 'email_otp';
}

function storedAccountOptionMatchesValue(option: StoredAccountOption, value: string): boolean {
  const normalizedValue = normalizeStoredAccountId(value);
  if (!normalizedValue) return false;
  const candidates = [option.walletId, option.displayName];
  for (const candidate of candidates) {
    if (normalizeStoredAccountId(candidate) === normalizedValue) return true;
  }
  return false;
}

function hasLocalPasskeyAccountOption(input: {
  accountOptions?: StoredAccountOption[];
  targetWalletId: string;
  inputValue: string;
}): boolean {
  const targetWalletId = normalizeStoredAccountId(input.targetWalletId);
  const inputValue = normalizeStoredAccountId(input.inputValue);
  if (!targetWalletId && !inputValue) return false;
  for (const option of input.accountOptions ?? []) {
    if (!isLocalPasskeyAccountOption(option)) continue;
    if (targetWalletId && storedAccountOptionMatchesValue(option, targetWalletId)) return true;
    if (inputValue && storedAccountOptionMatchesValue(option, inputValue)) return true;
  }
  return false;
}

export function usePasskeyAuthMenuController(
  props: Pick<
    PasskeyAuthMenuProps,
    | 'onLogin'
    | 'onRegister'
    | 'onSyncAccount'
    | 'emailOtpAuthPolicy'
    | 'defaultMode'
    | 'registrationAccountInput'
    | 'headings'
    | 'linkDeviceOptions'
    | 'socialLogin'
  >,
  runtime: PasskeyAuthMenuRuntime,
): PasskeyAuthMenuController {
  const secure = typeof window !== 'undefined' ? window.isSecureContext : true;
  const emailOtpAuthPolicy: EmailOtpAuthPolicy = props.emailOtpAuthPolicy || 'session';
  const registrationAccountInput: PasskeyAuthMenuRegistrationAccountInput =
    props.registrationAccountInput || 'implicit_wallet';
  const registrationUsesGeneratedWalletInput = registrationAccountInput === 'implicit_wallet';
  const registrationRequiresAccountInput =
    registrationAccountInput === 'sponsored_named_near_account';
  const loginTargetExists = runtime.passkeyCredentialExists;
  const registrationTargetExists = registrationRequiresAccountInput && runtime.accountExists;
  const defaultModeTargetExists = loginTargetExists || registrationTargetExists;
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
    accountExists: defaultModeTargetExists,
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
  const [waitingReason, setWaitingReason] = React.useState<'passkey' | 'social' | 'restore' | null>(
    null,
  );
  const [showScanDevice, setShowScanDevice] = React.useState(false);
  const [otpPromptState, setOtpPromptState] = React.useState<ActiveOtpPromptState | null>(null);
  const [registrationPromptState, setRegistrationPromptState] =
    React.useState<ActiveRegistrationPromptState | null>(null);
  const [postRecoveryRotationPromptState, setPostRecoveryRotationPromptState] =
    React.useState<ActivePostRecoveryRotationPromptState | null>(null);
  const [otpCode, setOtpCode] = React.useState('');
  const [otpRecoveryKey, setOtpRecoveryKey] = React.useState('');
  const [otpSubmitting, setOtpSubmitting] = React.useState(false);
  const [otpError, setOtpError] = React.useState<string>('');
  const [otpRerollBusy, setOtpRerollBusy] = React.useState(false);
  const [registrationSubmitting, setRegistrationSubmitting] = React.useState(false);
  const [registrationRerollBusy, setRegistrationRerollBusy] = React.useState(false);
  const [registrationError, setRegistrationError] = React.useState('');
  const [otpRecoveryKeyScanBusy, setOtpRecoveryKeyScanBusy] = React.useState(false);
  const [otpResendBusy, setOtpResendBusy] = React.useState(false);
  const [otpResendUntilMs, setOtpResendUntilMs] = React.useState(0);
  const [otpResendStatus, setOtpResendStatus] = React.useState('');
  const [otpResendNowMs, setOtpResendNowMs] = React.useState(() => Date.now());
  const [postRecoveryRotationBusy, setPostRecoveryRotationBusy] = React.useState(false);
  const [postRecoveryRotationError, setPostRecoveryRotationError] = React.useState('');
  const [methodError, setMethodError] = React.useState<string>('');
  const [passkeyRegistrationDraft, setPasskeyRegistrationDraft] = React.useState(
    createPasskeyRegistrationDraft,
  );

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
      if (next === AuthMenuMode.Register) {
        setCurrentValue('');
        clearPrefillMarkers();
      } else if (mode === AuthMenuMode.Login && next !== AuthMenuMode.Login) {
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

  const targetExists = mode === AuthMenuMode.Login ? loginTargetExists : registrationTargetExists;
  const passkeyRegistrationDraftWalletIdValue =
    passkeyRegistrationDraftWalletId(passkeyRegistrationDraft);
  const displayedCurrentValue =
    mode === AuthMenuMode.Register && registrationUsesGeneratedWalletInput
      ? passkeyRegistrationDraftWalletIdValue
      : currentValue;
  const shouldRestoreSyncedPasskeyOnLogin =
    mode === AuthMenuMode.Login &&
    typeof props.onSyncAccount === 'function' &&
    !loginTargetExists &&
    !hasLocalPasskeyAccountOption({
      accountOptions: runtime.accountOptions,
      targetWalletId: runtime.targetWalletId,
      inputValue: currentValue,
    });
  const { canShowContinue, canSubmit } = getProceedEligibility({
    mode,
    currentValue: displayedCurrentValue,
    targetExists,
    secure,
    registrationRequiresAccountInput,
    canRestoreSyncedPasskey: shouldRestoreSyncedPasskeyOnLogin,
  });
  const showAccountInput =
    mode === AuthMenuMode.Login ||
    registrationRequiresAccountInput ||
    registrationUsesGeneratedWalletInput;
  const accountInputReadOnly =
    mode === AuthMenuMode.Register && registrationUsesGeneratedWalletInput;
  const registrationActivationWallet =
    mode === AuthMenuMode.Register && registrationUsesGeneratedWalletInput
      ? passkeyRegistrationDraft.wallet
      : undefined;
  const onAccountInputReroll = React.useCallback(() => {
    setPasskeyRegistrationDraft(createPasskeyRegistrationDraft());
    setMethodError('');
  }, []);

  const passkeyAccountOptions = React.useMemo(() => {
    const byWalletAuth = new Map<string, StoredAccountOption>();
    for (const option of runtime.accountOptions ?? []) {
      const walletId = String(option.walletId || '').trim();
      if (!walletId) continue;
      const displayName = String(option.displayName || walletId).trim() || walletId;
      const authMethodKey = option.authMethod || 'passkey';
      byWalletAuth.set(`${walletId}:${authMethodKey}:${displayName}`, {
        walletId,
        displayName,
        ...(typeof option.signerSlot === 'number' ? { signerSlot: option.signerSlot } : {}),
        ...(option.authMethod ? { authMethod: option.authMethod } : {}),
      });
    }
    return [...byWalletAuth.values()].sort((a, b) => a.displayName.localeCompare(b.displayName));
  }, [runtime.accountOptions]);

  // If the user is attempting to register but we discover the account already exists,
  // automatically switch them to the Login tab.
  React.useEffect(() => {
    if (waiting) return;
    if (mode !== AuthMenuMode.Register) return;
    if (!registrationRequiresAccountInput) return;
    if (!registrationTargetExists) return;
    if (lastUserSelectedModeRef.current === AuthMenuMode.Register) return;
    setMode(AuthMenuMode.Login);
  }, [mode, registrationRequiresAccountInput, registrationTargetExists, setMode, waiting]);

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
    const cancel = otpPromptState?.onCancel;
    if (cancel) void Promise.resolve(cancel()).catch(() => {});
    const registrationCancel = registrationPromptState?.onCancel;
    if (registrationCancel) void Promise.resolve(registrationCancel()).catch(() => {});
    setWaiting(false);
    setWaitingReason(null);
    setOtpPromptState(null);
    setRegistrationPromptState(null);
    setPostRecoveryRotationPromptState(null);
    setOtpCode('');
    setOtpRecoveryKey('');
    setOtpError('');
    setRegistrationError('');
    setMethodError('');
    setOtpSubmitting(false);
    setRegistrationSubmitting(false);
    setOtpRerollBusy(false);
    setRegistrationRerollBusy(false);
    setOtpRecoveryKeyScanBusy(false);
    setOtpResendBusy(false);
    setOtpResendUntilMs(0);
    setOtpResendStatus('');
    setPostRecoveryRotationBusy(false);
    setPostRecoveryRotationError('');
    if (showScanDevice) {
      closeLinkDeviceView('user');
    } else {
      setShowScanDevice(false);
    }
    lastUserSelectedModeRef.current = null;
    resetToDefault();
    setCurrentValue('');
    clearPrefillMarkers();
  }, [
    otpPromptState,
    registrationPromptState,
    showScanDevice,
    closeLinkDeviceView,
    resetToDefault,
    setCurrentValue,
    clearPrefillMarkers,
  ]);

  const onProceed = React.useCallback(() => {
    if (!canSubmit) {
      if (mode === AuthMenuMode.Register) {
        if (!secure) {
          setMethodError('Passkey registration requires HTTPS or localhost.');
        } else if (registrationTargetExists) {
          setMethodError('This account already exists. Log in instead.');
        } else if (
          registrationUsesGeneratedWalletInput &&
          passkeyRegistrationDraftWalletIdValue.trim().length === 0
        ) {
          setMethodError('Could not generate a wallet name. Try again.');
        } else if (registrationRequiresAccountInput && currentValue.trim().length === 0) {
          setMethodError('Pick a username to create a passkey account.');
        }
      }
      return;
    }

    const shouldRestoreSyncedPasskey = shouldRestoreSyncedPasskeyOnLogin;
    setWaiting(true);
    setWaitingReason(shouldRestoreSyncedPasskey ? 'restore' : 'passkey');
    setPostRecoveryRotationPromptState(null);
    setPostRecoveryRotationError('');

    void (async () => {
      try {
        if (mode === AuthMenuMode.Login) {
          if (shouldRestoreSyncedPasskey) {
            await props.onSyncAccount?.();
          } else {
            await props.onLogin?.();
          }
          setWaiting(false);
          setWaitingReason(null);
          closeLinkDeviceView('flow');
          setMode(AuthMenuMode.Login);
        } else {
          const registrationRequest = createPasskeyAuthMenuRegistrationRequest({
            registrationAccountInput,
            passkeyRegistrationDraft,
            currentValue,
          });
          await props.onRegister?.(registrationRequest);
          setWaiting(false);
          setWaitingReason(null);
          setMode(AuthMenuMode.Login);
        }
      } catch (error) {
        if (mode === AuthMenuMode.Login) {
          setWaiting(false);
          setWaitingReason(null);
          closeLinkDeviceView('flow');
          setMode(mode);
          if (shouldRestoreSyncedPasskey) {
            setMethodError(getErrorMessage(error, 'Could not restore from synced passkey.'));
          }
          return;
        }
        onResetToStart();
      }
    })();
  }, [
    canSubmit,
    mode,
    secure,
    registrationTargetExists,
    currentValue,
    passkeyRegistrationDraft,
    passkeyRegistrationDraftWalletIdValue,
    registrationAccountInput,
    registrationUsesGeneratedWalletInput,
    registrationRequiresAccountInput,
    props.onLogin,
    props.onRegister,
    props.onSyncAccount,
    shouldRestoreSyncedPasskeyOnLogin,
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
      setPostRecoveryRotationPromptState(null);
      setPostRecoveryRotationError('');
      void (async () => {
        try {
          const result = await handler({ mode: socialMode, emailOtpAuthPolicy });
          const flowResult = result && typeof result === 'object' ? result : null;
          const isHeadlessOtpFlow =
            flowResult && 'kind' in flowResult && flowResult.kind === 'otp_flow';
          const isHeadlessRegistrationFlow =
            flowResult && 'kind' in flowResult && flowResult.kind === 'registration_flow';
          if (isHeadlessRegistrationFlow) {
            const mappedRegistrationFlowResult = registrationPromptFromGoogleEmailOtpFlow({
              flow: flowResult.flow,
              ...(flowResult.onComplete ? { onComplete: flowResult.onComplete } : {}),
            });
            setCurrentValue(mappedRegistrationFlowResult.username);
            setRegistrationError('');
            setRegistrationSubmitting(false);
            setRegistrationRerollBusy(false);
            setMethodError('');
            setOtpPromptState(null);
            setRegistrationPromptState(
              resolveRegistrationPrompt(mappedRegistrationFlowResult.registrationPrompt),
            );
            return;
          }
          const mappedFlowResult: {
            username?: string;
            otpPrompt?: PasskeyAuthMenuOtpPrompt;
          } | null = isHeadlessOtpFlow
            ? otpPromptFromGoogleEmailOtpFlow({
                flow: flowResult.flow,
                ...(flowResult.onComplete ? { onComplete: flowResult.onComplete } : {}),
              })
            : flowResult && 'otpPrompt' in flowResult
              ? flowResult
              : null;
          const username = String(mappedFlowResult?.username || '').trim();
          if (username) {
            setCurrentValue(username);
          }
          if (mappedFlowResult?.otpPrompt) {
            setOtpCode('');
            setOtpRecoveryKey('');
            setOtpError('');
            setRegistrationPromptState(null);
            setRegistrationError('');
            setOtpRerollBusy(false);
            setOtpRecoveryKeyScanBusy(false);
            setOtpResendBusy(false);
            setOtpResendUntilMs(0);
            setOtpResendStatus('');
            setMethodError('');
            setOtpPromptState(
              resolveOtpPrompt(mappedFlowResult.otpPrompt, username || undefined, {
                refreshLoginStateAfterSubmit: !isHeadlessOtpFlow,
              }),
            );
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

  const canRecoverAccountWithEmail = typeof props.socialLogin?.google === 'function';
  const onRecoverAccountWithEmail = React.useCallback(() => {
    onSocialLogin('google', AuthMenuMode.Login);
  }, [onSocialLogin]);

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
    const cancel = otpPromptState?.onCancel;
    if (cancel) void Promise.resolve(cancel()).catch(() => {});
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
  }, [otpPromptState]);

  const onPostRecoveryRotationDismiss = React.useCallback(() => {
    setPostRecoveryRotationPromptState(null);
    setPostRecoveryRotationBusy(false);
    setPostRecoveryRotationError('');
  }, []);

  const onPostRecoveryRotationSubmit = React.useCallback(() => {
    const prompt = postRecoveryRotationPromptState;
    if (!prompt || postRecoveryRotationBusy) return;
    setPostRecoveryRotationBusy(true);
    setPostRecoveryRotationError('');
    void (async () => {
      try {
        await runtime.seamsWeb.recovery.rotateEmailOtpRecoveryCodes({ walletId: prompt.walletId });
        await runtime.refreshLoginState(prompt.walletId).catch(() => {});
        setPostRecoveryRotationPromptState(null);
      } catch (error: unknown) {
        setPostRecoveryRotationError(
          getErrorMessage(error, 'Could not rotate recovery codes. Try again later.'),
        );
      } finally {
        setPostRecoveryRotationBusy(false);
      }
    })();
  }, [postRecoveryRotationBusy, postRecoveryRotationPromptState, runtime]);

  const onRegistrationPromptBack = React.useCallback(() => {
    const cancel = registrationPromptState?.onCancel;
    if (cancel) void Promise.resolve(cancel()).catch(() => {});
    setRegistrationPromptState(null);
    setRegistrationError('');
    setRegistrationSubmitting(false);
    setRegistrationRerollBusy(false);
  }, [registrationPromptState]);

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

  const onRegistrationRerollAccount = React.useCallback(() => {
    const activePrompt = registrationPromptState;
    if (!activePrompt || registrationSubmitting || registrationRerollBusy) return;
    setRegistrationRerollBusy(true);
    setRegistrationError('');
    void (async () => {
      try {
        const result = await activePrompt.onRerollAccount();
        const accountId = String(result?.accountId || result?.username || '').trim();
        const username = String(result?.username || result?.accountId || '').trim();
        const emailHint = String(result?.emailHint || '').trim();
        const title = String(result?.title || '').trim();
        const description = String(result?.description || '').trim();
        const submitLabel = String(result?.submitLabel || '').trim();
        const helperText = String(result?.helperText || '').trim();
        if (username) setCurrentValue(username);
        setRegistrationPromptState((current) =>
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
      } catch (error: unknown) {
        setRegistrationError(
          getErrorMessage(error, 'Could not choose another wallet name. Try again.'),
        );
      } finally {
        setRegistrationRerollBusy(false);
      }
    })();
  }, [registrationPromptState, registrationSubmitting, registrationRerollBusy, setCurrentValue]);

  const onRegistrationSubmit = React.useCallback(() => {
    const activePrompt = registrationPromptState;
    if (!activePrompt || registrationSubmitting) return;
    setRegistrationSubmitting(true);
    setRegistrationError('');
    void (async () => {
      try {
        await activePrompt.onSubmit();
        await runtime.refreshLoginState(activePrompt.accountId).catch(() => {});
        setRegistrationPromptState(null);
      } catch (error: unknown) {
        setRegistrationError(getErrorMessage(error, 'Wallet registration failed.'));
      } finally {
        setRegistrationSubmitting(false);
      }
    })();
  }, [registrationPromptState, registrationSubmitting, runtime]);

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
        const submitResult = await activePrompt.onSubmit(
          otpCode,
          recoveryKey ? { recoveryKey } : undefined,
        );
        const username = String(activePrompt.username || '').trim();
        if (username && activePrompt.refreshLoginStateAfterSubmit) {
          await runtime.refreshLoginState(username).catch(() => {});
        }
        const postRecoveryRotationPrompt = postRecoveryRotationPromptFromSubmitResult({
          result: submitResult,
          fallbackWalletId: String(activePrompt.accountId || activePrompt.username || '').trim(),
        });
        setOtpPromptState(null);
        setOtpCode('');
        setOtpRecoveryKey('');
        setPostRecoveryRotationError('');
        setPostRecoveryRotationPromptState(postRecoveryRotationPrompt);
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

  const registrationPrompt: PasskeyAuthMenuRegistrationPromptController | null =
    React.useMemo(() => {
      if (!registrationPromptState) return null;
      return {
        title: registrationPromptState.title,
        description: registrationPromptState.description,
        ...(registrationPromptState.emailHint
          ? { emailHint: registrationPromptState.emailHint }
          : {}),
        accountId: registrationPromptState.accountId,
        submitLabel: registrationPromptState.submitLabel,
        helperText: registrationPromptState.helperText,
        submitting: registrationSubmitting,
        ...(registrationError ? { error: registrationError } : {}),
        rerollAccountLabel: registrationRerollBusy
          ? 'Generating another name...'
          : 'Generate another name',
        rerollAccountDisabled: registrationSubmitting || registrationRerollBusy,
        onRerollAccount: onRegistrationRerollAccount,
        onSubmit: onRegistrationSubmit,
        onBack: onRegistrationPromptBack,
      };
    }, [
      registrationPromptState,
      registrationSubmitting,
      registrationError,
      registrationRerollBusy,
      onRegistrationRerollAccount,
      onRegistrationSubmit,
      onRegistrationPromptBack,
    ]);

  const postRecoveryRotationPrompt: PasskeyAuthMenuPostRecoveryRotationPromptController | null =
    React.useMemo(() => {
      if (!postRecoveryRotationPromptState) return null;
      return {
        walletId: postRecoveryRotationPromptState.walletId,
        activeRecoveryCodeCount: postRecoveryRotationPromptState.activeRecoveryCodeCount,
        expectedRecoveryCodeCount: postRecoveryRotationPromptState.expectedRecoveryCodeCount,
        rotating: postRecoveryRotationBusy,
        ...(postRecoveryRotationError ? { error: postRecoveryRotationError } : {}),
        onRotate: onPostRecoveryRotationSubmit,
        onDismiss: onPostRecoveryRotationDismiss,
      };
    }, [
      postRecoveryRotationBusy,
      postRecoveryRotationError,
      postRecoveryRotationPromptState,
      onPostRecoveryRotationSubmit,
      onPostRecoveryRotationDismiss,
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

  const activationRefreshLoginState = runtime.refreshLoginState;
  const onRegistrationActivationSurfaceStateChange = React.useCallback(
    (state: RegistrationActivationSurfaceState) => {
      switch (state.kind) {
        case 'idle':
        case 'mounting':
        case 'ready':
          setMethodError('');
          return;
        case 'starting':
          setMethodError('');
          setWaiting(true);
          setWaitingReason('passkey');
          setPostRecoveryRotationPromptState(null);
          setPostRecoveryRotationError('');
          return;
        case 'completed': {
          const result = state.result;
          if (!result.success) {
            setMethodError(result.error || 'Wallet registration failed.');
            setWaiting(false);
            setWaitingReason(null);
            return;
          }
          const walletId = String(result.walletId || '').trim();
          const displayAccountId = walletId;
          setMethodError('');
          setWaiting(false);
          setWaitingReason(null);
          closeLinkDeviceView('flow');
          setMode(AuthMenuMode.Login);
          if (walletId) {
            const username = extractUsernameFromAccountId(displayAccountId);
            if (username) setCurrentValue(username);
            void activationRefreshLoginState(walletId).catch(() => {});
          }
          return;
        }
        case 'cancelled':
          if (state.reason === 'disposed') return;
          setWaiting(false);
          setWaitingReason(null);
          if (state.reason === 'target_unavailable') {
            setMethodError('Passkey registration button is no longer available. Try again.');
            return;
          }
          if (state.reason === 'expired') {
            setMethodError('Passkey registration expired. Try again.');
            return;
          }
          setMethodError('Passkey registration was cancelled.');
          return;
        case 'failed':
          setMethodError(state.error || 'Wallet registration failed.');
          setWaiting(false);
          setWaitingReason(null);
          return;
        default:
          return assertNeverRegistrationActivationSurfaceState(state);
      }
    },
    [activationRefreshLoginState, closeLinkDeviceView, setCurrentValue, setMode],
  );

  return {
    mode,
    title,
    waiting,
    waitingReason,
    showScanDevice,
    otpPrompt,
    registrationPrompt,
    postRecoveryRotationPrompt,
    ...(methodError ? { methodError } : {}),
    currentValue: displayedCurrentValue,
    showAccountInput,
    accountInputReadOnly,
    accountInputRerollLabel:
      mode === AuthMenuMode.Register && registrationUsesGeneratedWalletInput
        ? 'Generate another wallet name'
        : undefined,
    accountInputRerollDisabled: waiting,
    ...(registrationActivationWallet ? { registrationActivationWallet } : {}),
    onAccountInputReroll:
      mode === AuthMenuMode.Register && registrationUsesGeneratedWalletInput
        ? onAccountInputReroll
        : undefined,
    targetExists,
    passkeyAccountOptions,
    postfixText: runtime.displayPostfix,
    isUsingExistingAccount: runtime.isUsingExistingAccount,
    secure,
    emailOtpAuthPolicy,
    canShowContinue,
    canSubmit,
    canRecoverAccountWithEmail,
    onSegmentChange,
    onInputChange,
    onProceed,
    onRecoverAccountWithEmail,
    onResetToStart,
    openScanDevice,
    onSocialLogin,
    onRegistrationActivationSurfaceStateChange,
    closeLinkDeviceView,
    linkDevice,
  };
}

export default usePasskeyAuthMenuController;

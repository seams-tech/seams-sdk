import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
  type MouseEvent,
} from 'react';

import { useSeams } from '../context';
import {
  classifyLinkDeviceFlowEvent,
  type LinkDeviceFlowEvent,
} from '../../core/types/sdkSentEvents';
import type {
  LinkedDeviceTargetEmailOtpActivationV1,
  LinkedDeviceTargetFactorActivationV1,
  LinkedDeviceTargetFactorV1,
  LinkedDeviceTargetPasskeyActivationV1,
} from '../../core/types/linkDevice';
import {
  isLinkedDeviceTargetEmailAddressV1,
  normalizeLinkedDeviceTargetEmailAddressV1,
} from '../../core/types/linkDevice';
import { toAccountId } from '../../core/types/accountIds';
import './ShowQRCode.css';

export interface ShowQRCodeProps {
  isOpen: boolean;
  onClose: () => void;
  onEvent: (event: LinkDeviceFlowEvent) => void;
  onError: (error: Error) => void;
}

type Device2LinkingTargetV1 =
  | {
      readonly targetFactor: Extract<LinkedDeviceTargetFactorV1, { readonly kind: 'passkey_prf' }>;
      readonly targetEmail?: never;
    }
  | {
      readonly targetFactor: Extract<LinkedDeviceTargetFactorV1, { readonly kind: 'email_otp' }>;
      readonly targetEmail: string;
    };

type Device2LinkingSelectFactorStateV1 =
  | ({ readonly kind: 'select_factor' } & Extract<
      Device2LinkingTargetV1,
      { readonly targetFactor: { readonly kind: 'passkey_prf' } }
    >)
  | ({ readonly kind: 'select_factor' } & Extract<
      Device2LinkingTargetV1,
      { readonly targetFactor: { readonly kind: 'email_otp' } }
    >);

type Device2LinkingState =
  | Device2LinkingSelectFactorStateV1
  | ({ readonly kind: 'starting' } & Device2LinkingTargetV1)
  | ({
      readonly kind: 'qr';
      readonly qrCodeDataURL: string;
      readonly lastPhase?: string;
      readonly lastMessage?: string;
    } & Device2LinkingTargetV1)
  | {
      readonly kind: 'passkey_activation';
      readonly targetFactor: Extract<LinkedDeviceTargetFactorV1, { readonly kind: 'passkey_prf' }>;
      readonly activation: LinkedDeviceTargetPasskeyActivationV1;
    }
  | {
      readonly kind: 'email_otp_activation';
      readonly targetFactor: Extract<LinkedDeviceTargetFactorV1, { readonly kind: 'email_otp' }>;
      readonly activation: LinkedDeviceTargetEmailOtpActivationV1;
    }
  | {
      readonly kind: 'failed';
      readonly message: string;
    };

type ActiveDevice2Flow = {
  readonly sessionId: number;
} & Device2LinkingTargetV1 & {
    cancelled: boolean;
  };

type Device2LinkingRuntime = {
  readonly startDevice2LinkingFlow: ReturnType<typeof useSeams>['startDevice2LinkingFlow'];
  readonly cancelDeviceLinking: ReturnType<typeof useSeams>['cancelDeviceLinking'];
  readonly refreshLoginState: ReturnType<typeof useSeams>['refreshLoginState'];
  readonly refreshAccountData: ReturnType<typeof useSeams>['refreshAccountData'];
  readonly setInputUsername: ReturnType<typeof useSeams>['setInputUsername'];
  readonly accountIdRaw: string;
  readonly onClose: ShowQRCodeProps['onClose'];
  readonly onEvent: ShowQRCodeProps['onEvent'];
  readonly onError: ShowQRCodeProps['onError'];
};

const DEFAULT_TARGET_FACTOR: Extract<LinkedDeviceTargetFactorV1, { readonly kind: 'passkey_prf' }> =
  { kind: 'passkey_prf' };
const FACTOR_FIELDSET_STYLE = {
  border: 0,
  margin: 0,
  padding: 0,
  width: '100%',
};

function targetFactorFromSelection(value: string): LinkedDeviceTargetFactorV1 | null {
  switch (value) {
    case 'passkey_prf':
      return { kind: 'passkey_prf' };
    case 'email_otp':
      return { kind: 'email_otp' };
    default:
      return null;
  }
}

function targetSelectionFromFactor(
  targetFactor: LinkedDeviceTargetFactorV1,
): Device2LinkingTargetV1 {
  return targetFactor.kind === 'email_otp' ? { targetFactor, targetEmail: '' } : { targetFactor };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'Device linking failed');
}

function stopPropagation(event: MouseEvent<HTMLDivElement>): void {
  event.stopPropagation();
}

function emailOtpDigits(code: string): readonly string[] {
  return code.padEnd(6, ' ').slice(0, 6).split('');
}

function renderEmailOtpDigit(digit: string, index: number) {
  return (
    <span key={index} className={`w3a-otp-slot${digit.trim() ? ' is-filled' : ''}`}>
      {digit}
    </span>
  );
}

function updateQrEventState(
  state: Device2LinkingState,
  event: LinkDeviceFlowEvent,
): Device2LinkingState {
  if (state.kind !== 'qr') return state;
  return {
    ...state,
    lastPhase: String(event.phase),
    lastMessage: event.message,
  };
}

function warnLinkedDeviceMenuRefresh(error: unknown): void {
  console.warn('Linked device activated, but the account menu refresh failed', error);
}

function reconcileActiveLinkedDevice(
  runtime: Device2LinkingRuntime,
  event: LinkDeviceFlowEvent,
  walletId: string,
): void {
  runtime.setInputUsername(walletId);
  runtime.onEvent(event);
  runtime.onClose();
  void Promise.all([runtime.refreshLoginState(walletId), runtime.refreshAccountData()]).catch(
    warnLinkedDeviceMenuRefresh,
  );
}

export function ShowQRCode({ isOpen, onClose, onEvent, onError }: ShowQRCodeProps) {
  const {
    startDevice2LinkingFlow,
    cancelDeviceLinking,
    refreshLoginState,
    refreshAccountData,
    setInputUsername,
    accountInputState,
    loginState,
  } = useSeams();
  const [deviceLinkingState, setDeviceLinkingState] = useState<Device2LinkingState>({
    kind: 'select_factor',
    targetFactor: DEFAULT_TARGET_FACTOR,
  });
  const [isCreatingPasskey, setIsCreatingPasskey] = useState(false);
  const flowSessionRef = useRef(0);
  const activeFlowRef = useRef<ActiveDevice2Flow | null>(null);
  const initialEmailSendSessionRef = useRef<number | null>(null);
  const flowRuntimeRef = useRef<Device2LinkingRuntime>({
    startDevice2LinkingFlow,
    cancelDeviceLinking,
    refreshLoginState,
    refreshAccountData,
    setInputUsername,
    accountIdRaw: '',
    onClose,
    onEvent,
    onError,
  });
  flowRuntimeRef.current = {
    startDevice2LinkingFlow,
    cancelDeviceLinking,
    refreshLoginState,
    refreshAccountData,
    setInputUsername,
    accountIdRaw: String(
      accountInputState?.targetAccountId || loginState?.nearAccountId || '',
    ).trim(),
    onClose,
    onEvent,
    onError,
  };

  const cancelActiveFlow = useCallback(() => {
    const flow = activeFlowRef.current;
    if (!flow) return;
    flow.cancelled = true;
    activeFlowRef.current = null;
    flowSessionRef.current += 1;
    void flowRuntimeRef.current.cancelDeviceLinking().catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!isOpen) return;

    setDeviceLinkingState({
      kind: 'select_factor',
      targetFactor: DEFAULT_TARGET_FACTOR,
    });
    setIsCreatingPasskey(false);
    initialEmailSendSessionRef.current = null;

    return cancelActiveFlow;
  }, [cancelActiveFlow, isOpen]);

  const handleFactorChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const targetFactor = targetFactorFromSelection(event.target.value);
    if (!targetFactor) return;
    const target = targetSelectionFromFactor(targetFactor);
    if (target.targetFactor.kind === 'email_otp') {
      setDeviceLinkingState({ kind: 'select_factor', ...target });
      return;
    }
    setDeviceLinkingState({ kind: 'select_factor', targetFactor: target.targetFactor });
  }, []);

  const handleTargetEmailAddressChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setDeviceLinkingState((previous) => {
      if (previous.kind !== 'select_factor' || previous.targetFactor.kind !== 'email_otp') {
        return previous;
      }
      return {
        kind: 'select_factor',
        targetFactor: previous.targetFactor,
        targetEmail: event.target.value,
      };
    });
  }, []);

  const handleStart = useCallback(() => {
    if (!isOpen || deviceLinkingState.kind !== 'select_factor') return;

    const runtime = flowRuntimeRef.current;
    let target: Device2LinkingTargetV1;
    try {
      target =
        deviceLinkingState.targetFactor.kind === 'email_otp'
          ? {
              targetFactor: deviceLinkingState.targetFactor,
              targetEmail: normalizeLinkedDeviceTargetEmailAddressV1(
                deviceLinkingState.targetEmail,
              ),
            }
          : { targetFactor: deviceLinkingState.targetFactor };
    } catch {
      return;
    }
    const flow: ActiveDevice2Flow = {
      sessionId: flowSessionRef.current + 1,
      ...target,
      cancelled: false,
    };
    flowSessionRef.current = flow.sessionId;
    activeFlowRef.current = flow;
    setDeviceLinkingState({ kind: 'starting', ...target });

    void (async () => {
      try {
        const { qrCodeDataURL } = await runtime.startDevice2LinkingFlow({
          ...target,
          ...(runtime.accountIdRaw ? { accountId: toAccountId(runtime.accountIdRaw) } : {}),
          options: {
            onEvent: (event: LinkDeviceFlowEvent) => {
              if (flow.cancelled || activeFlowRef.current !== flow) return;
              const outcome = classifyLinkDeviceFlowEvent(event);
              if (outcome.kind === 'active') {
                flow.cancelled = true;
                activeFlowRef.current = null;
                flowSessionRef.current += 1;
                reconcileActiveLinkedDevice(runtime, event, String(outcome.walletId));
                return;
              }
              if (outcome.kind === 'failed' || outcome.kind === 'invalid_active') {
                const error = new Error(event.message || 'Device linking failed');
                flow.cancelled = true;
                activeFlowRef.current = null;
                flowSessionRef.current += 1;
                setDeviceLinkingState({ kind: 'failed', message: error.message });
                runtime.onEvent(event);
                runtime.onError(error);
                return;
              }
              if (outcome.kind === 'cancelled') {
                flow.cancelled = true;
                activeFlowRef.current = null;
                flowSessionRef.current += 1;
                runtime.onEvent(event);
                runtime.onClose();
                return;
              }
              setDeviceLinkingState((previous) => updateQrEventState(previous, event));
              runtime.onEvent(event);
            },
            onError: (error: Error) => {
              if (flow.cancelled || activeFlowRef.current !== flow) return;
              setDeviceLinkingState({ kind: 'failed', message: error.message });
              runtime.onError(error);
            },
            onTargetFactorRequired: (activation: LinkedDeviceTargetFactorActivationV1) => {
              if (flow.cancelled || activeFlowRef.current !== flow) return;
              switch (activation.kind) {
                case 'linked_device_target_passkey_activation_v1':
                  if (flow.targetFactor.kind !== 'passkey_prf') {
                    runtime.onError(
                      new Error('Device-link target factor changed during activation'),
                    );
                    return;
                  }
                  setDeviceLinkingState({
                    kind: 'passkey_activation',
                    targetFactor: { kind: 'passkey_prf' },
                    activation,
                  });
                  return;
                case 'linked_device_target_email_otp_activation_v1':
                  if (flow.targetFactor.kind !== 'email_otp') {
                    runtime.onError(
                      new Error('Device-link target factor changed during activation'),
                    );
                    return;
                  }
                  setDeviceLinkingState({
                    kind: 'email_otp_activation',
                    targetFactor: { kind: 'email_otp' },
                    activation,
                  });
                  return;
                default:
                  return assertNeverTargetFactorActivation(activation);
              }
            },
          },
        });
        if (flow.cancelled || activeFlowRef.current !== flow) return;
        setDeviceLinkingState((previous) =>
          previous.kind === 'starting'
            ? {
                kind: 'qr',
                ...target,
                qrCodeDataURL,
              }
            : previous,
        );
      } catch (error: unknown) {
        if (flow.cancelled || activeFlowRef.current !== flow) return;
        const failure = error instanceof Error ? error : new Error(errorMessage(error));
        setDeviceLinkingState({ kind: 'failed', message: failure.message });
        runtime.onError(failure);
      }
    })();
  }, [deviceLinkingState, isOpen]);

  useEffect(() => {
    if (!isOpen || deviceLinkingState.kind !== 'email_otp_activation') return;
    const activation = deviceLinkingState.activation;
    if (activation.state.kind !== 'sending') return;
    const flow = activeFlowRef.current;
    if (!flow || flow.cancelled || initialEmailSendSessionRef.current === flow.sessionId) return;
    initialEmailSendSessionRef.current = flow.sessionId;
    void activation.sendCode().catch((error: unknown) => {
      setDeviceLinkingState((previous) => {
        if (previous.kind !== 'email_otp_activation' || previous.activation !== activation) {
          return previous;
        }
        return {
          ...previous,
          activation: {
            ...activation,
            state: {
              kind: 'unavailable',
              message: errorMessage(error),
            },
          },
        };
      });
    });
  }, [deviceLinkingState, isOpen]);

  const handlePasskeyError = useCallback((error: unknown) => {
    setIsCreatingPasskey(false);
    setDeviceLinkingState({ kind: 'failed', message: errorMessage(error) });
  }, []);

  const handleCreatePasskey = useCallback(async () => {
    if (deviceLinkingState.kind !== 'passkey_activation' || isCreatingPasskey) return;
    setIsCreatingPasskey(true);
    try {
      await deviceLinkingState.activation.createPasskey();
    } catch (error: unknown) {
      handlePasskeyError(error);
    }
  }, [deviceLinkingState, handlePasskeyError, isCreatingPasskey]);

  const handleEmailActivationError = useCallback(
    (activation: LinkedDeviceTargetEmailOtpActivationV1, error: unknown) => {
      setDeviceLinkingState((previous) => {
        if (previous.kind !== 'email_otp_activation' || previous.activation !== activation) {
          return previous;
        }
        return {
          ...previous,
          activation: {
            ...activation,
            state: {
              kind: 'unavailable',
              message: errorMessage(error),
            },
          },
        };
      });
    },
    [],
  );

  const handleChooseAnotherFactor = useCallback(() => {
    cancelActiveFlow();
    setDeviceLinkingState({
      kind: 'select_factor',
      targetFactor: DEFAULT_TARGET_FACTOR,
    });
  }, [cancelActiveFlow]);

  if (!isOpen) return null;

  switch (deviceLinkingState.kind) {
    case 'select_factor':
      return (
        <FactorSelection
          targetFactor={deviceLinkingState.targetFactor}
          targetEmail={deviceLinkingState.targetEmail ?? ''}
          onChange={handleFactorChange}
          onEmailAddressChange={handleTargetEmailAddressChange}
          onStart={handleStart}
        />
      );
    case 'starting':
      return <QrDisplay state={deviceLinkingState} />;
    case 'qr':
      return <QrDisplay state={deviceLinkingState} />;
    case 'passkey_activation':
      return <PasskeyActivation isCreating={isCreatingPasskey} onCreate={handleCreatePasskey} />;
    case 'email_otp_activation':
      return (
        <EmailOtpActivation
          activation={deviceLinkingState.activation}
          onError={handleEmailActivationError}
        />
      );
    case 'failed':
      return (
        <FailureView
          message={deviceLinkingState.message}
          onChooseAnother={handleChooseAnotherFactor}
        />
      );
    default:
      return assertNeverDevice2LinkingState(deviceLinkingState);
  }
}

function assertNeverDevice2LinkingState(value: never): never {
  throw new Error(`Unhandled Device 2 linking state: ${String(value)}`);
}

function assertNeverTargetFactorActivation(value: never): never {
  throw new Error(`Unhandled target-factor activation: ${String(value)}`);
}

function FactorSelection({
  targetFactor,
  targetEmail,
  onChange,
  onEmailAddressChange,
  onStart,
}: {
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly targetEmail: string;
  readonly onChange: (event: ChangeEvent<HTMLInputElement>) => void;
  readonly onEmailAddressChange: (event: ChangeEvent<HTMLInputElement>) => void;
  readonly onStart: () => void;
}) {
  const emailTargetSelected = targetFactor.kind === 'email_otp';
  const canStart = !emailTargetSelected || isLinkedDeviceTargetEmailAddressV1(targetEmail);
  return (
    <div className="qr-code-container" onClick={stopPropagation}>
      <div className="qr-body">
        <div className="w3a-otp-prompt" role="group" aria-labelledby="w3a-device-link-factor-title">
          <div className="w3a-otp-prompt-copy">
            <h2 id="w3a-device-link-factor-title" className="w3a-otp-title">
              Match your other device
            </h2>
            <p className="w3a-otp-description">
              Choose the unlock method for Device 2. Email code sends a one-time code to the address
              you enter.
            </p>
          </div>
          <fieldset style={FACTOR_FIELDSET_STYLE}>
            <legend className="w3a-field-label">Wallet unlock method</legend>
            <label>
              <input
                type="radio"
                name="w3a-device-link-target-factor"
                value="passkey_prf"
                checked={targetFactor.kind === 'passkey_prf'}
                onChange={onChange}
              />{' '}
              Passkey <span>(recommended)</span>
            </label>
            <label>
              <input
                type="radio"
                name="w3a-device-link-target-factor"
                value="email_otp"
                checked={targetFactor.kind === 'email_otp'}
                onChange={onChange}
              />{' '}
              Email code
            </label>
          </fieldset>
          {emailTargetSelected ? (
            <label className="w3a-device-link-email-field">
              <span className="w3a-field-label">Email address</span>
              <input
                type="email"
                name="w3a-device-link-target-email"
                autoComplete="email"
                value={targetEmail}
                onChange={onEmailAddressChange}
                aria-invalid={targetEmail.length > 0 && !canStart ? 'true' : undefined}
              />
            </label>
          ) : null}
          <p className="w3a-otp-helper">
            {emailTargetSelected
              ? 'The address is normalized before the QR code is created.'
              : 'Device 2 will create a new passkey for this wallet.'}
          </p>
          <button
            type="button"
            className="w3a-link-device-btn"
            onClick={onStart}
            disabled={!canStart}
          >
            Continue
          </button>
        </div>
      </div>
    </div>
  );
}

function QrDisplay({
  state,
}: {
  readonly state: Extract<Device2LinkingState, { readonly kind: 'starting' | 'qr' }>;
}) {
  const ready = state.kind === 'qr';
  return (
    <div className="qr-code-container" onClick={stopPropagation}>
      <div className="qr-body">
        <div className="qr-code-section">
          <div className="qr-code-display">
            {ready ? (
              <img
                src={state.qrCodeDataURL}
                alt="Device Linking QR Code"
                className="qr-code-image"
              />
            ) : (
              <div className="qr-code-placeholder">
                <span className="w3a-spinner" aria-hidden="true"></span>
              </div>
            )}
          </div>
          <div className="qr-header">
            <h2 className="qr-title">Scan and Link Device</h2>
          </div>
          <div className="qr-instruction">
            {ready
              ? 'Scan to backup your other device.'
              : 'Preparing a one-time code for your other device.'}
          </div>
          <div className="qr-status" role="status" aria-live="polite">
            {ready ? state.lastMessage || 'Waiting for device to scan' : 'Generating QR code'}
            <span className="animated-ellipsis"></span>
          </div>
        </div>
      </div>
    </div>
  );
}

function PasskeyActivation({
  isCreating,
  onCreate,
}: {
  readonly isCreating: boolean;
  readonly onCreate: () => Promise<void>;
}) {
  return (
    <div className="qr-code-container" onClick={stopPropagation}>
      <div className="qr-body">
        <div
          className="w3a-otp-prompt"
          role="group"
          aria-labelledby="w3a-device-link-passkey-title"
        >
          <div className="w3a-otp-prompt-copy">
            <h2 id="w3a-device-link-passkey-title" className="w3a-otp-title">
              Create a passkey
            </h2>
            <p className="w3a-otp-description">
              Confirm on this device to finish linking it to your wallet.
            </p>
          </div>
          <button
            type="button"
            className="w3a-link-device-btn"
            onClick={onCreate}
            disabled={isCreating}
            aria-busy={isCreating}
          >
            {isCreating ? 'Creating passkey…' : 'Create passkey'}
          </button>
        </div>
      </div>
    </div>
  );
}

function EmailOtpActivation({
  activation,
  onError,
}: {
  readonly activation: LinkedDeviceTargetEmailOtpActivationV1;
  readonly onError: (activation: LinkedDeviceTargetEmailOtpActivationV1, error: unknown) => void;
}) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [otpCode, setOtpCode] = useState('');
  const state = activation.state;

  useEffect(() => {
    if (state.kind !== 'code_input' && state.kind !== 'incorrect') return;
    inputRef.current?.focus();
  }, [activation, state.kind]);

  const handleCodeInput = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const input = event.currentTarget;
    const normalizedCode = input.value.replace(/\D/g, '').slice(0, 6);
    input.value = normalizedCode;
    input.setCustomValidity('');
    setOtpCode(normalizedCode);
    if (normalizedCode.length === 6) input.form?.requestSubmit();
  }, []);

  const handleSubmit = useCallback(
    (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const input = inputRef.current;
      if (!input || isSubmitting) return;
      const code = input.value.trim();
      if (!/^\d{6}$/.test(code)) {
        input.setCustomValidity('Enter the 6-digit email code.');
        input.reportValidity();
        return;
      }
      input.setCustomValidity('');
      setIsSubmitting(true);
      void activation
        .submitCode(code)
        .catch((error: unknown) => {
          onError(activation, error);
        })
        .finally(() => {
          setIsSubmitting(false);
        });
    },
    [activation, isSubmitting, onError],
  );

  const handleResend = useCallback(() => {
    if (isResending) return;
    setOtpCode('');
    setIsResending(true);
    void activation
      .resendCode()
      .catch((error: unknown) => {
        onError(activation, error);
      })
      .finally(() => {
        setIsResending(false);
      });
  }, [activation, isResending, onError]);

  const handleRetry = useCallback(() => {
    if (isSending) return;
    setIsSending(true);
    void activation
      .sendCode()
      .catch((error: unknown) => {
        onError(activation, error);
      })
      .finally(() => {
        setIsSending(false);
      });
  }, [activation, isSending, onError]);

  return (
    <div className="qr-code-container" onClick={stopPropagation}>
      <div className="qr-body">
        <div className="w3a-otp-prompt" role="group" aria-labelledby="w3a-device-link-email-title">
          <div className="w3a-otp-prompt-copy">
            <h2 id="w3a-device-link-email-title" className="w3a-otp-title">
              Confirm with an email code
            </h2>
            {state.kind !== 'unavailable' && (
              <p className="w3a-otp-description">
                Use the code sent to <strong>{state.maskedEmailHint}</strong>. The destination is
                managed by your wallet and cannot be changed here.
              </p>
            )}
          </div>
          {state.kind === 'sending' && (
            <div className="qr-status" role="status" aria-live="polite">
              Sending your email code…
            </div>
          )}
          {state.kind === 'resending' && (
            <div className="qr-status" role="status" aria-live="polite">
              Sending a new email code…
            </div>
          )}
          {state.kind === 'completed' && (
            <div className="qr-status" role="status" aria-live="polite">
              Email code accepted. Finishing device activation…
            </div>
          )}
          {(state.kind === 'code_input' ||
            state.kind === 'submitting' ||
            state.kind === 'incorrect') && (
            <form className="w3a-otp-code-field" onSubmit={handleSubmit}>
              <label className="w3a-field-label" htmlFor="w3a-device-link-email-otp">
                Email code
              </label>
              <input
                ref={inputRef}
                id="w3a-device-link-email-otp"
                className="w3a-otp-input"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                aria-label="Email verification code"
                aria-invalid={state.kind === 'incorrect'}
                aria-describedby={
                  state.kind === 'incorrect' ? 'w3a-device-link-email-error' : undefined
                }
                value={otpCode}
                disabled={state.kind === 'submitting' || isSubmitting}
                onChange={handleCodeInput}
              />
              <div className="w3a-otp-slots" aria-hidden="true">
                {emailOtpDigits(otpCode).map(renderEmailOtpDigit)}
              </div>
              {state.kind === 'incorrect' && (
                <p id="w3a-device-link-email-error" className="w3a-otp-error" role="alert">
                  {state.message}
                </p>
              )}
              <button
                type="submit"
                className="w3a-link-device-btn"
                disabled={state.kind === 'submitting' || isSubmitting}
                aria-busy={state.kind === 'submitting' || isSubmitting}
              >
                {state.kind === 'submitting' || isSubmitting ? 'Checking code…' : 'Confirm code'}
              </button>
            </form>
          )}
          {state.kind === 'expired' && (
            <p className="w3a-otp-error" role="alert">
              {state.message}
            </p>
          )}
          {state.kind === 'unavailable' && (
            <>
              <p className="w3a-otp-error" role="alert">
                {state.message}
              </p>
              <button
                type="button"
                className="w3a-link-device-btn"
                onClick={handleRetry}
                disabled={isSending}
                aria-busy={isSending}
              >
                {isSending ? 'Trying again…' : 'Send code again'}
              </button>
            </>
          )}
          {(state.kind === 'code_input' ||
            state.kind === 'incorrect' ||
            state.kind === 'expired') && (
            <button
              type="button"
              className="w3a-otp-resend"
              onClick={handleResend}
              disabled={isResending}
              aria-busy={isResending}
            >
              {isResending ? 'Sending…' : 'Resend code'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function FailureView({
  message,
  onChooseAnother,
}: {
  readonly message: string;
  readonly onChooseAnother: () => void;
}) {
  return (
    <div className="w3a-link-device-failure" onClick={stopPropagation}>
      <div className="w3a-link-device-failure-icon">
        <LinkFailedIcon />
      </div>
      <h2 className="qr-title">Couldn&apos;t link device</h2>
      <p className="w3a-link-device-failure-detail" role="alert">
        {message || 'Device linking failed'}
      </p>
      <button type="button" className="w3a-link-device-btn" onClick={onChooseAnother}>
        Choose another factor
      </button>
    </div>
  );
}

function LinkFailedIcon() {
  return (
    <svg
      width="26"
      height="26"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M9 17H7A5 5 0 1 1 7 7h2" />
      <path d="M15 7h2a5 5 0 0 1 3.54 8.54" />
      <path d="m2 2 20 20" />
      <path d="M8 12h3" />
    </svg>
  );
}

import React from 'react';
import { ArrowLeftIcon, FingerprintIcon } from './ui/icons';
import { SegmentedControl } from './ui/SegmentedControl';
import { PasskeyInput } from './ui/PasskeyInput';
import { ContentSwitcher } from './ui/ContentSwitcher';
import { SocialProviders } from './ui/SocialProviders';
import QRCodeIcon from '../QRCodeIcon';
import { ArrowRightAnim } from '../ArrowRightAnim';
import { AuthMenuMode, type PasskeyAuthMenuProps } from './types';
import { getGoogleSsoButtonLabel, getGoogleSsoHelperText } from './socialCopy';
import { usePasskeyAuthMenuRuntime } from './adapters/tatchi';
import { usePasskeyAuthMenuController } from './controller/usePasskeyAuthMenuController';
import { useSDKEvents } from './controller/useSDKEvents';

type CSSVarStyle = React.CSSProperties & {
  [key: `--${string}`]: string | number | undefined;
};

const LazyShowQRCode = React.lazy(() =>
  import('../ShowQRCode').then((m) => ({ default: m.ShowQRCode })),
);

const preloadShowQRCode = () => import('../ShowQRCode').then(() => undefined);

const OTP_CODE_LENGTH = 6;

export const PasskeyAuthMenuClient: React.FC<PasskeyAuthMenuProps> = ({
  onLogin,
  onRegister,
  onSyncAccount,
  emailOtpAuthPolicy,
  linkDeviceOptions,
  header,
  defaultMode,
  style,
  className,
  socialLogin,
  loadingScreenDelayMs,
  headings,
  showSDKEvents = false,
}) => {
  const runtime = usePasskeyAuthMenuRuntime();
  const { withSdkEventsHandler } = useSDKEvents({ sdkFlow: runtime.sdkFlow });

  const onLoginWithSDKEvents = React.useMemo(
    () => withSdkEventsHandler('login', onLogin, 60_000),
    [onLogin, withSdkEventsHandler],
  );
  const onRegisterWithSDKEvents = React.useMemo(
    () => withSdkEventsHandler('register', onRegister, 90_000),
    [onRegister, withSdkEventsHandler],
  );
  const onSyncWithSDKEvents = React.useMemo(
    () => withSdkEventsHandler('sync', onSyncAccount, 120_000),
    [onSyncAccount, withSdkEventsHandler],
  );

  const controller = usePasskeyAuthMenuController(
    {
      onLogin: onLoginWithSDKEvents,
      onRegister: onRegisterWithSDKEvents,
      onSyncAccount: onSyncWithSDKEvents,
      emailOtpAuthPolicy,
      defaultMode,
      headings,
      linkDeviceOptions,
      socialLogin,
    },
    runtime,
  );

  const prefetchQRCode = React.useCallback(() => {
    void preloadShowQRCode().catch(() => {});
  }, []);
  const otpInputRef = React.useRef<HTMLInputElement | null>(null);
  const lastAutoOtpSubmitRef = React.useRef('');

  const segActiveBg = 'var(--w3a-passkey-auth-menu2-seg-active-bg)';
  const rootStyle = React.useMemo<CSSVarStyle>(
    () => ({
      ...style,
      ...(loadingScreenDelayMs != null
        ? { '--w3a-waiting-delay': `${loadingScreenDelayMs}ms` }
        : null),
    }),
    [loadingScreenDelayMs, style],
  );

  const waitingSDKEventsText = React.useMemo(() => {
    if (!showSDKEvents) return '';
    if (
      controller.mode !== AuthMenuMode.Register &&
      controller.mode !== AuthMenuMode.Login &&
      controller.mode !== AuthMenuMode.Sync
    ) {
      return '';
    }
    const text = runtime.sdkFlow.eventsText?.trim() ?? '';
    if (text.length > 0) {
      const lastLine = text.split('\n').filter(Boolean).slice(-1)[0] ?? '';
      return lastLine;
    }
    if (controller.waitingReason === 'social') {
      return '';
    }
    return controller.waiting ? 'Awaiting SDK events…' : '';
  }, [
    controller.mode,
    controller.waiting,
    controller.waitingReason,
    runtime.sdkFlow.eventsText,
    showSDKEvents,
  ]);

  const otpDigits = React.useMemo(() => {
    const code = controller.otpPrompt?.code ?? '';
    return Array.from({ length: OTP_CODE_LENGTH }, (_, index) => code[index] ?? '');
  }, [controller.otpPrompt?.code]);

  React.useEffect(() => {
    const prompt = controller.otpPrompt;
    if (!prompt) {
      lastAutoOtpSubmitRef.current = '';
      return;
    }
    const code = prompt.code;
    if (prompt.recoveryKeyRequired && !prompt.recoveryKeyReady) {
      lastAutoOtpSubmitRef.current = '';
      return;
    }
    if (!/^\d{6}$/.test(code) || prompt.submitting) {
      if (code.length < OTP_CODE_LENGTH) lastAutoOtpSubmitRef.current = '';
      return;
    }
    if (lastAutoOtpSubmitRef.current === code) return;
    lastAutoOtpSubmitRef.current = code;
    prompt.onSubmit();
  }, [controller.otpPrompt]);

  return (
    <div
      className={`w3a-signup-menu-root${className ? ` ${className}` : ''}`}
      data-mode={controller.mode}
      data-waiting={controller.waiting}
      data-scan-device={controller.showScanDevice}
      data-otp-prompt={controller.otpPrompt ? 'true' : 'false'}
      style={rootStyle}
    >
      <ContentSwitcher
        waiting={controller.waiting}
        waitingText={
          controller.waitingReason === 'social'
            ? 'Waiting for Google SSO authentication...'
            : controller.mode === AuthMenuMode.Register
              ? 'Creating passkey wallet…'
              : controller.mode === AuthMenuMode.Sync
                ? 'Syncing account…'
                : 'Signing in…'
        }
        waitingSubtext=""
        waitingSDKEventsText={waitingSDKEventsText}
        backButton={
          <button
            aria-label="Back"
            type="button"
            onClick={() => {
              if (controller.otpPrompt) {
                controller.otpPrompt.onBack();
                return;
              }
              if (controller.showScanDevice) {
                controller.closeLinkDeviceView('user');
                return;
              }
              controller.onResetToStart();
            }}
            className={`w3a-back-button${
              controller.waiting || controller.showScanDevice || controller.otpPrompt
                ? ' is-visible'
                : ''
            }`}
          >
            <ArrowLeftIcon size={18} strokeWidth={2.25} style={{ display: 'block' }} />
          </button>
        }
        showScanDevice={controller.showScanDevice}
        showQRCodeElement={
          <React.Suspense
            fallback={
              <div className="qr-loading">
                <p>Loading QR…</p>
              </div>
            }
          >
            <LazyShowQRCode
              isOpen={controller.linkDevice.isOpen}
              onClose={controller.linkDevice.onClose}
              onEvent={controller.linkDevice.onEvent}
              onError={controller.linkDevice.onError}
            />
          </React.Suspense>
        }
      >
        <div className="w3a-header">
          {header ?? (
            <div>
              <div className="w3a-title">{controller.title.title}</div>
              <div className="w3a-subhead">{controller.title.subtitle}</div>
            </div>
          )}
        </div>

        {controller.otpPrompt ? (
          <div className="w3a-otp-prompt" aria-live="polite">
            <div className="w3a-otp-prompt-copy">
              <div className="w3a-otp-title">{controller.otpPrompt.title}</div>
              <p className="w3a-otp-description">{controller.otpPrompt.description}</p>
              {controller.otpPrompt.accountId ? (
                <div className="w3a-otp-account" title={controller.otpPrompt.accountId}>
                  <span className="w3a-otp-account-label">Wallet</span>
                  <span className="w3a-otp-account-value">{controller.otpPrompt.accountId}</span>
                </div>
              ) : null}
              {controller.otpPrompt.onRerollAccount ? (
                <button
                  type="button"
                  className="w3a-otp-reroll"
                  onClick={controller.otpPrompt.onRerollAccount}
                  disabled={controller.otpPrompt.rerollAccountDisabled}
                >
                  {controller.otpPrompt.rerollAccountLabel || 'Try another wallet name'}
                </button>
              ) : null}
            </div>
            <label className="w3a-field-label" htmlFor="w3a-email-otp-code">
              Email code
            </label>
            <div
              className="w3a-otp-code-field"
              data-disabled={controller.otpPrompt.submitting ? 'true' : 'false'}
              onClick={() => otpInputRef.current?.focus()}
            >
              <input
                ref={otpInputRef}
                id="w3a-email-otp-code"
                className="w3a-otp-input"
                value={controller.otpPrompt.code}
                onChange={(event) => controller.otpPrompt?.onCodeChange(event.currentTarget.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') controller.otpPrompt?.onSubmit();
                }}
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]*"
                maxLength={OTP_CODE_LENGTH}
                disabled={controller.otpPrompt.submitting}
              />
              <div className="w3a-otp-slots" aria-hidden="true">
                {otpDigits.map((digit, index) => (
                  <span key={index} className={`w3a-otp-slot${digit ? ' is-filled' : ''}`}>
                    {digit}
                  </span>
                ))}
              </div>
            </div>
            {controller.otpPrompt.recoveryKeyRequired ? (
              <div className="w3a-recovery-key-section">
                <div className="w3a-recovery-key-label-row">
                  <label className="w3a-field-label" htmlFor="w3a-email-otp-recovery-key">
                    {controller.otpPrompt.recoveryKeyLabel}
                  </label>
                  {controller.otpPrompt.onRecoveryKeyScan ? (
                    <button
                      type="button"
                      className="w3a-recovery-key-scan"
                      onClick={controller.otpPrompt.onRecoveryKeyScan}
                      disabled={
                        controller.otpPrompt.submitting ||
                        controller.otpPrompt.recoveryKeyScanBusy
                      }
                    >
                      {controller.otpPrompt.recoveryKeyScanLabel || 'Scan recovery key'}
                    </button>
                  ) : null}
                </div>
                <input
                  id="w3a-email-otp-recovery-key"
                  className="w3a-recovery-key-input"
                  value={controller.otpPrompt.recoveryKey}
                  onChange={(event) =>
                    controller.otpPrompt?.onRecoveryKeyChange(event.currentTarget.value)
                  }
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') controller.otpPrompt?.onSubmit();
                  }}
                  inputMode="text"
                  autoComplete="off"
                  autoCapitalize="characters"
                  spellCheck={false}
                  placeholder={controller.otpPrompt.recoveryKeyPlaceholder}
                  maxLength={39}
                  disabled={controller.otpPrompt.submitting}
                />
                <p className="w3a-otp-helper">{controller.otpPrompt.recoveryKeyHelperText}</p>
              </div>
            ) : null}
            {controller.otpPrompt.error ? (
              <p className="w3a-otp-error" role="alert">
                {controller.otpPrompt.error}
              </p>
            ) : (
              <p className="w3a-otp-helper">{controller.otpPrompt.helperText}</p>
            )}
            <button
              type="button"
              className="w3a-auth-method-btn w3a-auth-method-btn-primary"
              onClick={controller.otpPrompt.onSubmit}
              disabled={
                controller.otpPrompt.submitting ||
                controller.otpPrompt.code.length !== 6 ||
                (controller.otpPrompt.recoveryKeyRequired &&
                  !controller.otpPrompt.recoveryKeyReady)
              }
            >
              {controller.otpPrompt.submitting ? 'Unlocking…' : controller.otpPrompt.submitLabel}
            </button>
            {controller.otpPrompt.onResend ? (
              <button
                type="button"
                className="w3a-otp-resend"
                onClick={controller.otpPrompt.onResend}
                disabled={controller.otpPrompt.resendDisabled}
              >
                {controller.otpPrompt.resendLabel || 'Resend Code'}
              </button>
            ) : null}
          </div>
        ) : (
          <>
            <PasskeyInput
              value={controller.currentValue}
              onChange={controller.onInputChange}
              placeholder={
                controller.mode === AuthMenuMode.Register
                  ? 'Pick a username'
                  : controller.mode === AuthMenuMode.Sync
                    ? 'Leave blank to discover accounts'
                    : 'Enter your username'
              }
              postfixText={controller.postfixText}
              isUsingExistingAccount={controller.isUsingExistingAccount}
              accountExists={runtime.accountExists}
              accountOptions={controller.passkeyAccountOptions}
              onProceed={controller.onProceed}
              mode={controller.mode}
              secure={controller.secure}
              waiting={controller.waiting}
            />

            <SegmentedControl
              items={[
                { value: AuthMenuMode.Register, label: 'Register', className: 'register' },
                { value: AuthMenuMode.Login, label: 'Login', className: 'login' },
                { value: AuthMenuMode.Sync, label: 'Sync', className: 'sync' },
              ]}
              value={controller.mode}
              onValueChange={(v) => controller.onSegmentChange(v as AuthMenuMode)}
              activeBg={segActiveBg}
            />

            {controller.mode !== AuthMenuMode.Login ? (
              <div className="w3a-seg-help-row">
                <div className="w3a-seg-help" aria-live="polite">
                  {controller.mode === AuthMenuMode.Register && 'Create a new account'}
                  {controller.mode === AuthMenuMode.Sync && 'Sync account (iCloud/Chrome sync)'}
                </div>
              </div>
            ) : null}

            {(controller.mode === AuthMenuMode.Login ||
              controller.mode === AuthMenuMode.Register) && (
              <div className="w3a-auth-methods">
                <div className="w3a-auth-method-stack">
                  {controller.mode === AuthMenuMode.Login && (
                    <>
                      <button
                        type="button"
                        onClick={controller.onProceed}
                        className="w3a-auth-method-btn w3a-auth-method-btn-primary"
                        disabled={!controller.canSubmit || controller.waiting}
                      >
                        <FingerprintIcon size={22} style={{ display: 'block' }} />
                        <span>Continue with Passkey</span>
                        <ArrowRightAnim size={16} className="w3a-auth-method-arrow" />
                      </button>
                      <SocialProviders
                        socialLogin={socialLogin}
                        providers={['google']}
                        disabled={controller.waiting}
                        onProviderClick={() =>
                          controller.onSocialLogin('google', AuthMenuMode.Login)
                        }
                        providerCopy={{
                          google: {
                            buttonLabel: getGoogleSsoButtonLabel(AuthMenuMode.Login),
                            helperText: getGoogleSsoHelperText(
                              AuthMenuMode.Login,
                              controller.emailOtpAuthPolicy,
                            ),
                          },
                        }}
                      />
                    </>
                  )}

                  {controller.mode === AuthMenuMode.Register && (
                    <>
                      <button
                        type="button"
                        onClick={controller.onProceed}
                        className="w3a-auth-method-btn w3a-auth-method-btn-primary"
                        disabled={!controller.canSubmit || controller.waiting}
                      >
                        Create with Passkey
                      </button>
                      <SocialProviders
                        socialLogin={socialLogin}
                        providers={['google']}
                        disabled={controller.waiting}
                        onProviderClick={() =>
                          controller.onSocialLogin('google', AuthMenuMode.Register)
                        }
                        providerCopy={{
                          google: {
                            buttonLabel: getGoogleSsoButtonLabel(AuthMenuMode.Register),
                            helperText: getGoogleSsoHelperText(
                              AuthMenuMode.Register,
                              controller.emailOtpAuthPolicy,
                            ),
                          },
                        }}
                      />
                    </>
                  )}
                </div>
                {controller.methodError ? (
                  <p className="w3a-method-error" role="alert">
                    {controller.methodError}
                  </p>
                ) : null}
              </div>
            )}

            {controller.mode === AuthMenuMode.Login && (
              <div className="w3a-scan-device-row">
                <div className="w3a-section-divider">
                  <span className="w3a-section-divider-text">Other options</span>
                </div>
                <div className="w3a-secondary-actions">
                  <button
                    type="button"
                    onClick={() => {
                      controller.openScanDevice();
                    }}
                    onPointerEnter={prefetchQRCode}
                    onFocus={prefetchQRCode}
                    onTouchStart={prefetchQRCode}
                    className="w3a-link-device-btn"
                  >
                    <QRCodeIcon width={18} height={18} strokeWidth={2} />
                    Scan and Link Device
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </ContentSwitcher>
    </div>
  );
};

export default PasskeyAuthMenuClient;

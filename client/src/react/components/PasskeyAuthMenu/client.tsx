import React from 'react';
import { ArrowLeftIcon, MailIcon } from './ui/icons';
import { SegmentedControl } from './ui/SegmentedControl';
import { PasskeyInput } from './ui/PasskeyInput';
import { ContentSwitcher } from './ui/ContentSwitcher';
import { SocialProviders } from './ui/SocialProviders';
import QRCodeIcon from '../QRCodeIcon';
import { AuthMenuMode, type PasskeyAuthMenuProps } from './types';
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

export const PasskeyAuthMenuClient: React.FC<PasskeyAuthMenuProps> = ({
  onLogin,
  onRegister,
  onSyncAccount,
  onEmailOtpLogin,
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
      onEmailOtpLogin,
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
    return controller.waiting ? 'Awaiting SDK events…' : '';
  }, [controller.mode, controller.waiting, runtime.sdkFlow.eventsText, showSDKEvents]);

  return (
    <div
      className={`w3a-signup-menu-root${className ? ` ${className}` : ''}`}
      data-mode={controller.mode}
      data-waiting={controller.waiting}
      data-scan-device={controller.showScanDevice}
      style={rootStyle}
    >
      <ContentSwitcher
        waiting={controller.waiting}
        waitingText={
          controller.mode === AuthMenuMode.Register
            ? 'Creating passkey wallet…'
            : controller.mode === AuthMenuMode.Sync
              ? 'Syncing account…'
              : 'Signing in…'
        }
        waitingSDKEventsText={waitingSDKEventsText}
        backButton={
          <button
            aria-label="Back"
            onClick={() => {
              controller.onResetToStart();
            }}
            className={`w3a-back-button${controller.waiting || controller.showScanDevice ? ' is-visible' : ''}`}
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
          canProceed={controller.canShowContinue}
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

        <div className="w3a-seg-help-row">
          <div className="w3a-seg-help" aria-live="polite">
            {controller.mode === AuthMenuMode.Login && 'Choose a login method'}
            {controller.mode === AuthMenuMode.Register && 'Create a new account'}
            {controller.mode === AuthMenuMode.Sync && 'Sync account (iCloud/Chrome sync)'}
          </div>
        </div>

        {(controller.mode === AuthMenuMode.Login || controller.mode === AuthMenuMode.Register) && (
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
                    Continue with Passkey
                  </button>
                  <button
                    type="button"
                    onClick={controller.onEmailOtpLogin}
                    className="w3a-auth-method-btn w3a-auth-method-btn-secondary"
                    disabled={!onEmailOtpLogin || controller.waiting}
                  >
                    <MailIcon size={18} strokeWidth={2} style={{ display: 'block' }} />
                    Continue with Email OTP
                  </button>
                  <SocialProviders
                    socialLogin={socialLogin}
                    providers={['google']}
                    disabled={controller.waiting}
                    onProviderClick={controller.onSocialLogin}
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
                    onProviderClick={controller.onSocialLogin}
                  />
                </>
              )}
            </div>
            {controller.mode === AuthMenuMode.Login && (
              <div className="w3a-auth-method-note" aria-live="polite">
                {controller.emailOtpAuthPolicy === 'per_operation'
                  ? 'Email OTP is a convenience login. Passkey is more secure, and OTP will be required for each operation.'
                  : 'Email OTP is a convenience login. Passkey is more secure, and OTP remains warm only until session expiry or logout.'}
              </div>
            )}
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
      </ContentSwitcher>
    </div>
  );
};

export default PasskeyAuthMenuClient;

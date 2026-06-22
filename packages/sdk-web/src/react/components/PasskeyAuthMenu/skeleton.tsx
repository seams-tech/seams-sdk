import React from 'react';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { ArrowLeftIcon, FingerprintIcon } from './ui/icons';
import { SocialProviders } from './ui/SocialProviders';
import QRCodeIcon from '../QRCodeIcon';
import { ArrowRightAnim } from '../ArrowRightAnim';
import { PasskeyAuthMenuThemeScope } from './themeScope';
import { useTheme } from '../theme';
import { getModeTitle, resolveDefaultMode } from './controller/mode';
import { AuthMenuMode, type AuthMenuHeadings } from './types';
import { getGoogleSsoButtonLabel, getGoogleSsoHelperText } from './socialCopy';

export interface PasskeyAuthMenuSkeletonProps {
  className?: string;
  style?: React.CSSProperties;
  /** Best-effort to match the hydrated UI default tab. */
  defaultMode?: AuthMenuMode;
  /** Best-effort to match the hydrated UI headings. */
  headings?: AuthMenuHeadings;
  /** Best-effort to match the hydrated UI Email OTP signing-session policy. */
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
}

export const PasskeyAuthMenuSkeletonInner = React.forwardRef<
  HTMLDivElement,
  PasskeyAuthMenuSkeletonProps
>(({ className, style, defaultMode, headings, emailOtpAuthPolicy }, ref) => {
  const mode = resolveDefaultMode(false, defaultMode);
  const resolvedEmailOtpAuthPolicy: EmailOtpAuthPolicy = emailOtpAuthPolicy || 'session';
  const title = getModeTitle(mode, headings ?? null);
  const placeholder =
    mode === AuthMenuMode.Register ? 'Pick a username' : 'Enter your username';
  const segActiveWidth = 'calc((100% - 14px) / 2)';
  const segActiveX =
    mode === AuthMenuMode.Login
      ? `calc(5px + ${segActiveWidth} + 4px)`
      : '5px';

  return (
    <div
      ref={ref}
      className={`w3a-signup-menu-root w3a-skeleton${className ? ` ${className}` : ''}`}
      style={style}
      data-mode={mode}
      data-waiting="false"
      data-scan-device="false"
    >
      <div className="w3a-content-switcher">
        <button aria-label="Back" type="button" className="w3a-back-button" disabled>
          <ArrowLeftIcon size={18} strokeWidth={2.25} style={{ display: 'block' }} />
        </button>

        <div className="w3a-content-area">
          <div className="w3a-content-sizer">
            <div className="w3a-signin-menu">
              <div className="w3a-header">
                <div>
                  <div className="w3a-title">{title.title}</div>
                  <div className="w3a-subhead">{title.subtitle}</div>
                </div>
              </div>

              <div className="w3a-passkey-row">
                <div className="w3a-input-pill">
                  <div className="w3a-input-wrap">
                    <input
                      type="text"
                      name="passkey"
                      disabled
                      placeholder={placeholder}
                      className="w3a-input"
                      aria-disabled="true"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      inputMode="text"
                      style={{ pointerEvents: 'none' }}
                    />
                  </div>
                </div>
              </div>

              <div className="w3a-seg">
                <div
                  className="w3a-seg-active"
                  style={{
                    width: segActiveWidth,
                    transform: `translateX(${segActiveX})`,
                    opacity: 0.9,
                    background: 'var(--w3a-passkey-auth-menu2-seg-active-bg)',
                  }}
                />
                <div className="w3a-seg-grid">
                  <button
                    type="button"
                    aria-pressed={mode === AuthMenuMode.Register}
                    className={`w3a-seg-btn${mode === AuthMenuMode.Register ? ' is-active' : ''} register`}
                    disabled
                  >
                    Register
                  </button>
                  <button
                    type="button"
                    aria-pressed={mode === AuthMenuMode.Login}
                    className={`w3a-seg-btn${mode === AuthMenuMode.Login ? ' is-active' : ''} login`}
                    disabled
                  >
                    Login
                  </button>
                </div>
              </div>

              {(mode === AuthMenuMode.Login || mode === AuthMenuMode.Register) && (
                <div className="w3a-auth-methods">
                  <div className="w3a-auth-method-stack">
                    {mode === AuthMenuMode.Login && (
                      <>
                        <button
                          className="w3a-auth-method-btn w3a-auth-method-btn-primary"
                          disabled
                        >
                          <FingerprintIcon size={22} style={{ display: 'block' }} />
                          <span>Continue with Passkey</span>
                          <ArrowRightAnim size={16} className="w3a-auth-method-arrow" />
                        </button>
                        <SocialProviders
                          socialLogin={{ google: () => undefined }}
                          providers={['google']}
                          disabled
                          providerCopy={{
                            google: {
                              buttonLabel: getGoogleSsoButtonLabel(AuthMenuMode.Login),
                              helperText: getGoogleSsoHelperText(
                                AuthMenuMode.Login,
                                resolvedEmailOtpAuthPolicy,
                              ),
                            },
                          }}
                        />
                      </>
                    )}
                    {mode === AuthMenuMode.Register && (
                      <>
                        <button
                          className="w3a-auth-method-btn w3a-auth-method-btn-primary"
                          disabled
                        >
                          Create with Passkey
                        </button>
                        <SocialProviders
                          socialLogin={{ google: () => undefined }}
                          providers={['google']}
                          disabled
                          providerCopy={{
                            google: {
                              buttonLabel: getGoogleSsoButtonLabel(AuthMenuMode.Register),
                              helperText: getGoogleSsoHelperText(
                                AuthMenuMode.Register,
                                resolvedEmailOtpAuthPolicy,
                              ),
                            },
                          }}
                        />
                      </>
                    )}
                  </div>
                </div>
              )}

              {mode === AuthMenuMode.Login && (
                <div className="w3a-scan-device-row">
                  <div className="w3a-section-divider">
                    <span className="w3a-section-divider-text">Other options</span>
                  </div>
                  <div className="w3a-secondary-actions">
                    <button className="w3a-link-device-btn" disabled>
                      <QRCodeIcon width={18} height={18} strokeWidth={2} />
                      Scan and Link Device
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});
PasskeyAuthMenuSkeletonInner.displayName = 'PasskeyAuthMenuSkeletonInner';

export const PasskeyAuthMenuSkeleton: React.FC<PasskeyAuthMenuSkeletonProps> = (props) => {
  const { theme, tokens } = useTheme();
  return (
    <PasskeyAuthMenuThemeScope theme={theme} tokens={tokens}>
      <PasskeyAuthMenuSkeletonInner {...props} />
    </PasskeyAuthMenuThemeScope>
  );
};

export default PasskeyAuthMenuSkeleton;

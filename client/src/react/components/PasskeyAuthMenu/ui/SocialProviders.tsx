import React from 'react';
import type { PasskeyAuthMenuSocialLoginHandler } from '../types';
import { ChromeIcon, AppleIcon, AtSignIcon } from './icons';
import { ArrowRightAnim } from '../../ArrowRightAnim';

export type SocialLoginHandlers = {
  google?: PasskeyAuthMenuSocialLoginHandler;
  x?: PasskeyAuthMenuSocialLoginHandler;
  apple?: PasskeyAuthMenuSocialLoginHandler;
};

export interface SocialProvidersProps {
  socialLogin?: SocialLoginHandlers;
  providers?: Array<keyof SocialLoginHandlers>;
  disabled?: boolean;
  onProviderClick?: (provider: keyof SocialLoginHandlers) => void;
  providerCopy?: Partial<
    Record<keyof SocialLoginHandlers, { buttonLabel?: string; helperText?: string }>
  >;
}

const iconByKey: Record<
  keyof SocialLoginHandlers,
  { Icon: React.ComponentType<any>; label: string }
> = {
  google: { Icon: ChromeIcon, label: 'Google' },
  x: { Icon: AtSignIcon, label: 'X' },
  apple: { Icon: AppleIcon, label: 'Apple' },
};

export const SocialProviders: React.FC<SocialProvidersProps> = ({
  socialLogin,
  providers,
  disabled = false,
  onProviderClick,
  providerCopy,
}) => {
  const helperIdBase = React.useId();
  const visibleProviders =
    providers && providers.length > 0
      ? providers
      : (Object.keys(iconByKey) as Array<keyof SocialLoginHandlers>).filter(
          (provider) => typeof socialLogin?.[provider] === 'function',
        );
  if (!visibleProviders.length) return null;

  return (
    <div className="w3a-auth-method-stack w3a-social-stack">
      {visibleProviders.map((provider) => {
        const { Icon, label } = iconByKey[provider];
        const copy = providerCopy?.[provider];
        const hasHandler = typeof socialLogin?.[provider] === 'function';
        const buttonLabel =
          copy?.buttonLabel ||
          (provider === 'google' ? 'Continue with Google' : `Continue with ${label}`);
        const helperText = copy?.helperText?.trim();
        const helperId = helperText ? `${helperIdBase}-${provider}` : undefined;
        return (
          <div key={provider} className="w3a-social-provider">
            <button
              type="button"
              className="w3a-auth-method-btn w3a-auth-method-btn-secondary"
              onClick={() => {
                if (!hasHandler) return;
                onProviderClick?.(provider);
              }}
              disabled={disabled || !hasHandler}
              aria-describedby={helperId}
            >
              <Icon size={18} style={{ display: 'block' }} />
              <span>{buttonLabel}</span>
              <ArrowRightAnim size={16} className="w3a-auth-method-arrow" />
            </button>
            {helperText ? (
              <p id={helperId} className="w3a-auth-method-note w3a-social-helper">
                {helperText}
              </p>
            ) : null}
          </div>
        );
      })}
    </div>
  );
};

export default SocialProviders;

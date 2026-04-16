import React from 'react';
import { ChromeIcon, AppleIcon, AtSignIcon } from './icons';

export type SocialLoginHandlers = {
  google?: () => string | void | Promise<string | void>;
  x?: () => string | void | Promise<string | void>;
  apple?: () => string | void | Promise<string | void>;
};

export interface SocialProvidersProps {
  socialLogin?: SocialLoginHandlers;
  providers?: Array<keyof SocialLoginHandlers>;
  disabled?: boolean;
  onProviderClick?: (provider: keyof SocialLoginHandlers) => void;
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
}) => {
  const enabledProviders = (providers || (Object.keys(iconByKey) as Array<keyof SocialLoginHandlers>))
    .filter((provider) => typeof socialLogin?.[provider] === 'function');
  if (!enabledProviders.length) return null;

  return (
    <div className="w3a-auth-method-stack w3a-social-stack">
      {enabledProviders.map((provider) => {
        const { Icon, label } = iconByKey[provider];
        const buttonLabel =
          provider === 'google' ? 'Continue with Google' : `Continue with ${label}`;
        return (
          <button
            key={provider}
            type="button"
            className="w3a-auth-method-btn w3a-auth-method-btn-secondary"
            onClick={() => onProviderClick?.(provider)}
            disabled={disabled}
          >
            <Icon size={18} style={{ display: 'block' }} />
            {buttonLabel}
          </button>
        );
      })}
    </div>
  );
};

export default SocialProviders;

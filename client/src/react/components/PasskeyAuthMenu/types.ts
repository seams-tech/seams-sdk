import React from 'react';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { EmailOtpAuthPolicy } from '@/core/types/tatchi';
import {
  AuthMenuMode,
  AuthMenuModeMap,
  type AuthMenuModeLabel,
  type AuthMenuHeadings,
} from './authMenuTypes';

export { AuthMenuMode, AuthMenuModeMap };
export type { AuthMenuModeLabel, AuthMenuHeadings };

export type PasskeyAuthMenuOtpPrompt = {
  title?: string;
  description?: string;
  emailHint?: string;
  accountId?: string;
  submitLabel?: string;
  helperText?: string;
  onSubmit: (otpCode: string) => void | Promise<unknown>;
  onRerollAccount?: () =>
    | Promise<{ username?: string; accountId?: string; emailHint?: string } | void>
    | { username?: string; accountId?: string; emailHint?: string }
    | void;
  onResend?: () =>
    | Promise<{ challengeId?: string; emailHint?: string } | void>
    | { challengeId?: string; emailHint?: string }
    | void;
  resendDebounceMs?: number;
};

export type PasskeyAuthMenuSocialLoginResult = {
  username?: string;
  otpPrompt?: PasskeyAuthMenuOtpPrompt;
};

export type PasskeyAuthMenuSocialLoginHandler = (args: {
  mode: AuthMenuMode;
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
}) => void | PasskeyAuthMenuSocialLoginResult | Promise<void | PasskeyAuthMenuSocialLoginResult>;

export interface PasskeyAuthMenuProps {
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onLogin?: () => void | Promise<unknown>;
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onRegister?: () => void | Promise<unknown>;
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onSyncAccount?: () => void | Promise<unknown>;
  /** App-selected Email OTP signing-session policy exposed through the auth menu. */
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  /** Display SDK progress event messages under the waiting screen. */
  showSDKEvents?: boolean;
  /**
   * Optional delay (in ms) before the waiting screen animation starts.
   * Useful to hold the loading view briefly to avoid jarring flashes
   * during fast transitions. Defaults to 100ms.
   */
  loadingScreenDelayMs?: number;
  /** Optional callbacks for the link-device QR flow */
  linkDeviceOptions?: {
    onEvent?: (event: LinkDeviceFlowEvent) => void;
    onError?: (error: Error) => void;
    /** Called when the user manually cancels the link-device flow */
    onCancelled?: () => void;
  };
  /** Optional custom header element rendered when not waiting */
  header?: React.ReactElement;
  defaultMode?: AuthMenuMode;
  style?: React.CSSProperties;
  className?: string;
  /** Optional custom headings for each mode */
  headings?: AuthMenuHeadings;
  /**
   * Optional social login hooks. Google SSO should return an Email OTP prompt
   * once the external app session is established and the OTP challenge is sent.
   * If omitted or all undefined, the social buttons are hidden.
   */
  socialLogin?: {
    google?: PasskeyAuthMenuSocialLoginHandler;
    x?: PasskeyAuthMenuSocialLoginHandler;
    apple?: PasskeyAuthMenuSocialLoginHandler;
  };
}

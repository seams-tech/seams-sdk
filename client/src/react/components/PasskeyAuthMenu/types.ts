import React from 'react';
import type { DeviceLinkingSSEEvent } from '@/core/types/sdkSentEvents';
import type { EmailOtpAuthPolicy } from '@/core/types/tatchi';
import {
  AuthMenuMode,
  AuthMenuModeMap,
  type AuthMenuModeLabel,
  type AuthMenuHeadings,
} from './authMenuTypes';

export { AuthMenuMode, AuthMenuModeMap };
export type { AuthMenuModeLabel, AuthMenuHeadings };

export interface PasskeyAuthMenuProps {
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onLogin?: () => void | Promise<unknown>;
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onRegister?: () => void | Promise<unknown>;
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onSyncAccount?: () => void | Promise<unknown>;
  /** Return a Promise to keep the waiting screen visible until the Email OTP flow completes. */
  onEmailOtpLogin?: (args: { policy: EmailOtpAuthPolicy }) => void | Promise<unknown>;
  /** App-selected Email OTP retention policy exposed through the auth menu. */
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
    onEvent?: (event: DeviceLinkingSSEEvent) => void;
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
   * Optional social login hooks. Provide a function per provider that returns
   * the derived username (e.g., email/handle) after the external auth flow.
   * If omitted or all undefined, the social buttons are hidden.
   */
  socialLogin?: {
    google?: () => string | void | Promise<string | void>;
    x?: () => string | void | Promise<string | void>;
    apple?: () => string | void | Promise<string | void>;
  };
}

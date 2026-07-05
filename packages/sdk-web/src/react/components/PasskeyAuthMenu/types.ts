import React from 'react';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { EmailOtpAuthPolicy, WalletSession } from '@/core/types/seams';
import type {
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthResolvedMode,
} from '@/SeamsWeb';
import type { RegisterWalletInput, WalletId } from '@shared/utils/registrationIntent';
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
  walletId?: string;
  accountId?: string;
  submitLabel?: string;
  helperText?: string;
  recoveryKey?: {
    required?: boolean;
    label?: string;
    placeholder?: string;
    helperText?: string;
    scanLabel?: string;
    onScan?: () => string | void | Promise<string | void>;
  };
  onSubmit: (
    otpCode: string,
    context?: { recoveryKey?: string },
  ) => void | Promise<unknown> | PasskeyAuthMenuOtpSubmitResult;
  onRerollAccount?: () =>
    | Promise<
        | {
            username?: string;
            walletId?: string;
            accountId?: string;
            emailHint?: string;
            title?: string;
            description?: string;
            submitLabel?: string;
            helperText?: string;
            codeDelivery?: 'sent' | 'reused';
          }
        | void
      >
    | {
        username?: string;
        walletId?: string;
        accountId?: string;
        emailHint?: string;
        title?: string;
        description?: string;
        submitLabel?: string;
        helperText?: string;
        codeDelivery?: 'sent' | 'reused';
      }
    | void;
  onResend?: () =>
    | Promise<{ challengeId?: string; emailHint?: string } | void>
    | { challengeId?: string; emailHint?: string }
    | void;
  onCancel?: () => void | Promise<void>;
  resendDebounceMs?: number;
};

export type PasskeyAuthMenuOtpSubmitResult = {
  walletId?: string;
  activeRecoveryWrappedEnrollmentEscrowCount?: number;
};

export type PasskeyAuthMenuRegistrationPrompt = {
  username?: string;
  walletId?: string;
  accountId?: string;
  emailHint?: string;
  title?: string;
  description?: string;
  submitLabel?: string;
  helperText?: string;
  rerollAccountLabel?: string;
  onSubmit: () => void | Promise<unknown>;
  onRerollAccount?: () =>
    | Promise<
        | {
            username?: string;
            walletId?: string;
            accountId?: string;
            emailHint?: string;
            title?: string;
            description?: string;
            submitLabel?: string;
            helperText?: string;
          }
        | void
      >
    | {
        username?: string;
        walletId?: string;
        accountId?: string;
        emailHint?: string;
        title?: string;
        description?: string;
        submitLabel?: string;
        helperText?: string;
      }
    | void;
  onCancel?: () => void | Promise<void>;
};

export type PasskeyAuthMenuSocialCompletion = (result: {
  walletId: WalletId;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
  session: WalletSession;
}) => void | Promise<void>;

export type PasskeyAuthMenuSocialLoginResult =
  | {
      kind?: 'otp_prompt';
      username?: string;
      otpPrompt?: PasskeyAuthMenuOtpPrompt;
      onComplete?: PasskeyAuthMenuSocialCompletion;
    }
  | {
      kind: 'otp_flow';
      flow: GoogleEmailOtpWalletAuthFlow;
      onComplete?: PasskeyAuthMenuSocialCompletion;
    }
  | {
      kind: 'registration_flow';
      flow: GoogleEmailOtpWalletAuthRegistrationFlow;
      onComplete?: PasskeyAuthMenuSocialCompletion;
    };

export type PasskeyAuthMenuSocialLoginHandler = (args: {
  mode: AuthMenuMode;
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
}) => void | PasskeyAuthMenuSocialLoginResult | Promise<void | PasskeyAuthMenuSocialLoginResult>;

export type PasskeyAuthMenuRegistrationAccountInput =
  | 'implicit_wallet'
  | 'sponsored_named_near_account';

export type PasskeyAuthMenuProvidedRegistrationWallet = Extract<
  RegisterWalletInput,
  { kind: 'provided' }
>;

export type PasskeyAuthMenuRegistrationRequest =
  | {
      kind: 'implicit_wallet';
      wallet: PasskeyAuthMenuProvidedRegistrationWallet;
    }
  | {
      kind: 'sponsored_named_near_account';
      wallet: PasskeyAuthMenuProvidedRegistrationWallet;
    };

export interface PasskeyAuthMenuProps {
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onLogin?: () => void | Promise<unknown>;
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onRegister?: (request: PasskeyAuthMenuRegistrationRequest) => void | Promise<unknown>;
  /** Return a Promise to keep the waiting screen visible until the flow completes. */
  onSyncAccount?: () => void | Promise<unknown>;
  /** App-selected Email OTP signing-session policy exposed through the auth menu. */
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  /** Registration wallet/account input policy. Defaults to implicit wallet registration. */
  registrationAccountInput?: PasskeyAuthMenuRegistrationAccountInput;
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
   * Optional social login hooks. Google SSO login returns an Email OTP prompt.
   * Google SSO registration returns a registration prompt because Google has
   * already verified the email address.
   * If omitted or all undefined, the social buttons are hidden.
   */
  socialLogin?: {
    google?: PasskeyAuthMenuSocialLoginHandler;
    x?: PasskeyAuthMenuSocialLoginHandler;
    apple?: PasskeyAuthMenuSocialLoginHandler;
  };
}

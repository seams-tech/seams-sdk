import type { AppearanceConfig } from '@/core/types/seams';
import type { HostedAuthMenuExternalProvider } from '../../../shared/messages';
import type {
  GoogleEmailOtpWalletAuthDelivery,
  GoogleEmailOtpWalletAuthPromptCopy,
} from '@/SeamsWeb/publicApi/types';

/**
 * The view model is normalized by the wallet-host controller before it reaches
 * the element. Keeping the model here makes the component usable by a future
 * host controller without coupling it to Lit, React, or the message router.
 */
export type AuthMenuSurfaceStatus =
  | {
      readonly kind: 'preparing';
      readonly message: string;
    }
  | {
      readonly kind: 'ready';
    }
  | {
      readonly kind: 'input_required';
    }
  | {
      readonly kind: 'performing';
      readonly message: string;
    }
  | {
      readonly kind: 'error';
      readonly message: string;
    }
  | {
      readonly kind: 'expired';
      readonly message: string;
    };

interface AuthMenuViewModelCommon {
  readonly appearance: AppearanceConfig;
  readonly hostname: string;
  readonly closeLabel: string;
  readonly heading: string;
  readonly subtitle: string;
  readonly ctaLabel: string;
  readonly showProgress: boolean;
  readonly enabledExternalProviders?: readonly HostedAuthMenuExternalProvider[];
  readonly status: AuthMenuSurfaceStatus;
}

export type AuthMenuLoginViewModel = AuthMenuViewModelCommon & {
  readonly kind: 'passkey';
  readonly mode: 'login';
  readonly accountOptions: readonly AuthMenuAccountOption[];
  readonly selectedWalletId: string | null;
  readonly passkeyName?: never;
  readonly passkeyNameLabel?: never;
};

export type AuthMenuRegisterViewModel = AuthMenuViewModelCommon & {
  readonly kind: 'passkey';
  readonly mode: 'register';
  readonly showRegistrationInput: boolean;
  readonly passkeyNameReadOnly: boolean;
  readonly passkeyName: string;
  readonly passkeyNameLabel: string;
};

export type AuthMenuAccountOption = Readonly<{
  readonly walletId: string;
  readonly displayName: string;
}>;

export type AuthMenuGoogleLoginViewModel = AuthMenuViewModelCommon & {
  readonly kind: 'google_otp_login';
  readonly mode: 'login';
  readonly emailHint: string;
  readonly walletId: string;
  readonly prompt: GoogleEmailOtpWalletAuthPromptCopy;
  readonly delivery: GoogleEmailOtpWalletAuthDelivery;
  readonly otpCode: string;
  readonly resendBusy: boolean;
  readonly submitBusy: boolean;
  readonly error?: string;
  readonly passkeyName?: never;
  readonly passkeyNameLabel?: never;
};

export type AuthMenuGoogleRegistrationViewModel = AuthMenuViewModelCommon & {
  readonly kind: 'google_registration';
  readonly mode: 'register';
  readonly emailHint: string;
  readonly walletId: string;
  readonly prompt: GoogleEmailOtpWalletAuthPromptCopy;
  readonly rerollBusy: boolean;
  readonly submitBusy: boolean;
  readonly error?: string;
  readonly passkeyName?: never;
  readonly passkeyNameLabel?: never;
};

export type AuthMenuLinkDeviceState =
  | { readonly kind: 'loading'; readonly message: string }
  | {
      readonly kind: 'ready';
      readonly qrCodeDataURL: string;
      readonly message: string;
    }
  | { readonly kind: 'error'; readonly message: string };

export type AuthMenuLinkDeviceViewModel = AuthMenuViewModelCommon & {
  readonly kind: 'link_device';
  readonly mode: 'login' | 'register';
  readonly linkDevice: AuthMenuLinkDeviceState;
  readonly passkeyName?: never;
  readonly passkeyNameLabel?: never;
};

export type AuthMenuViewModel =
  | AuthMenuLoginViewModel
  | AuthMenuRegisterViewModel
  | AuthMenuGoogleLoginViewModel
  | AuthMenuGoogleRegistrationViewModel
  | AuthMenuLinkDeviceViewModel;

export type AuthMenuCloseReason = 'close_button' | 'escape';

export type AuthMenuIntent =
  | {
      readonly kind: 'close';
      readonly reason: AuthMenuCloseReason;
    }
  | {
      readonly kind: 'mode_selected';
      readonly mode: 'login' | 'register';
    }
  | {
      readonly kind: 'back';
    }
  | {
      readonly kind: 'link_device_open';
    }
  | {
      readonly kind: 'registration_reroll';
    }
  | {
      readonly kind: 'submit';
      readonly mode: 'login';
    }
  | {
      readonly kind: 'submit';
      readonly mode: 'register';
      readonly passkeyName: string;
    }
  | {
      readonly kind: 'passkey_name_changed';
      readonly passkeyName: string;
    }
  | {
      readonly kind: 'login_account_selected';
      readonly walletId: string;
    }
  | {
      readonly kind: 'external_auth';
      readonly provider: HostedAuthMenuExternalProvider;
    }
  | {
      readonly kind: 'google_otp_code_changed';
      readonly code: string;
    }
  | {
      readonly kind: 'google_otp_resend';
    }
  | {
      readonly kind: 'google_otp_submit';
    }
  | {
      readonly kind: 'google_registration_reroll';
    }
  | {
      readonly kind: 'google_registration_complete';
    }
  | {
      readonly kind: 'retry';
    };

export const AUTH_MENU_INTENT_EVENT = 'w3a-auth-menu-intent' as const;

export type AuthMenuIntentEvent = CustomEvent<AuthMenuIntent>;

export function isAuthMenuIntent(value: unknown): value is AuthMenuIntent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  switch (record.kind) {
    case 'close':
      return record.reason === 'close_button' || record.reason === 'escape';
    case 'mode_selected':
      return record.mode === 'login' || record.mode === 'register';
    case 'back':
    case 'link_device_open':
    case 'registration_reroll':
      return true;
    case 'submit':
      return (
        record.mode === 'login' ||
        (record.mode === 'register' && typeof record.passkeyName === 'string')
      );
    case 'passkey_name_changed':
      return typeof record.passkeyName === 'string';
    case 'login_account_selected':
      return typeof record.walletId === 'string';
    case 'external_auth':
      return record.provider === 'google';
    case 'google_otp_code_changed':
      return typeof record.code === 'string';
    case 'google_otp_resend':
    case 'google_otp_submit':
    case 'google_registration_reroll':
    case 'google_registration_complete':
    case 'retry':
      return true;
    default:
      return false;
  }
}

export function dispatchAuthMenuIntent(target: EventTarget, detail: AuthMenuIntent): boolean {
  return target.dispatchEvent(
    new CustomEvent<AuthMenuIntent>(AUTH_MENU_INTENT_EVENT, {
      bubbles: true,
      composed: true,
      detail,
    }),
  );
}

export function isAuthMenuLoadingStatus(status: AuthMenuSurfaceStatus): boolean {
  return status.kind === 'preparing' || status.kind === 'performing';
}

export function isAuthMenuReady(viewModel: AuthMenuViewModel): boolean {
  return viewModel.status.kind === 'ready';
}

export function isAuthMenuActionReady(viewModel: AuthMenuViewModel): boolean {
  if (!isAuthMenuReady(viewModel)) return false;
  switch (viewModel.kind) {
    case 'google_otp_login':
      return !viewModel.submitBusy && /^\d{6}$/.test(viewModel.otpCode);
    case 'google_registration':
      return !viewModel.rerollBusy && !viewModel.submitBusy;
    case 'link_device':
      return false;
    case 'passkey':
      return viewModel.mode === 'login'
        ? true
        : !viewModel.showRegistrationInput || viewModel.passkeyName.trim().length > 0;
  }
}

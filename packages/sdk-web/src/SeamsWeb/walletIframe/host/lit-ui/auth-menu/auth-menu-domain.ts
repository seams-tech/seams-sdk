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
/**
 * Discriminated by PRESENTATION, not by which internal phase produced it.
 *
 * The surface can only do three things — show the form, show the waiting view,
 * or show the form with a message — so those are the three kinds. An earlier
 * shape split the busy case in two ('preparing' vs 'performing'), a provenance
 * distinction the surface could not act on: it rendered the waiting view for
 * one and the form for the other, so every author who reached for the wrong
 * one silently got a form where they meant a spinner. That exact mistake
 * shipped four times. Here "busy but rendering the form" cannot be expressed.
 *
 * `headline` is required on `busy` so entering a wait forces naming what is
 * being waited on, rather than inheriting whatever copy the previous view had.
 */
export type AuthMenuSurfaceStatus =
  | {
      /** Renders the form. */
      readonly kind: 'idle';
      /**
       * - `actionable`: primary control is live.
       * - `awaiting_input`: live once the required input is filled in.
       * - `arming`: background preparation in flight; control not yet usable.
       */
      readonly interaction: 'actionable' | 'awaiting_input' | 'arming';
    }
  | {
      /** Renders the waiting view. The only busy state there is. */
      readonly kind: 'busy';
      /** Names the wait, e.g. "Verifying your email code". */
      readonly headline: string;
      /** Optional secondary line, shown only when the host opts into progress. */
      readonly detail?: string;
    }
  | {
      /** Renders the form plus a message; the primary control stays live. */
      readonly kind: 'recoverable';
      readonly reason: 'error' | 'expired';
      readonly message: string;
    };

/** The waiting headline for the passkey ceremony itself. */
export function passkeyCeremonyHeadline(mode: 'login' | 'register'): string {
  return mode === 'register' ? 'Creating passkey wallet…' : 'Signing in…';
}

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
  | {
      readonly kind: 'passkey_required';
      readonly message: string;
    }
  | {
      readonly kind: 'creating_passkey';
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
      readonly kind: 'link_device_create_passkey';
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
    case 'link_device_create_passkey':
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
  return status.kind === 'busy';
}

export function isAuthMenuReady(viewModel: AuthMenuViewModel): boolean {
  const status = viewModel.status;
  return status.kind === 'idle' && status.interaction === 'actionable';
}

/**
 * A failed or expired preparation is recoverable by acting again, so the
 * primary control stays live and re-prepares on click. Only genuinely
 * in-flight work or a required input disables it.
 */
export function isAuthMenuActionable(viewModel: AuthMenuViewModel): boolean {
  const status = viewModel.status;
  if (status.kind === 'recoverable') return true;
  return status.kind === 'idle' && status.interaction === 'actionable';
}

export function isAuthMenuActionReady(viewModel: AuthMenuViewModel): boolean {
  if (!isAuthMenuActionable(viewModel)) return false;
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

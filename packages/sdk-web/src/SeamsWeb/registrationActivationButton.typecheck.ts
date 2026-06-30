import type {
  CreatePasskeyRegistrationActivationSurfaceArgs,
  RegistrationActivationButtonPresentation,
} from './publicApi/types';
import { walletIdFromString } from '@shared/utils/registrationIntent';

export const validOutlineOverlayPresentation: RegistrationActivationButtonPresentation = {
  kind: 'outline_overlay',
  label: 'Create with Passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
  iframeButtonStyle: {
    width: '100%',
    borderRadius: '999px',
    boxShadow: '0 12px 24px rgba(0, 0, 0, 0.18)',
  },
};

export const validIframeButtonPresentation: RegistrationActivationButtonPresentation = {
  kind: 'iframe_button',
  label: 'Create with Passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
  iframeVisualStyle: {
    width: '100%',
    borderRadius: '999px',
  },
  shadowPaddingPx: 16,
};

export const validActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  presentation: validOutlineOverlayPresentation,
};

// @ts-expect-error activation surfaces require the displayed provided wallet ID.
export const missingWalletActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  presentation: validOutlineOverlayPresentation,
};

export const serverAllocatedActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  // @ts-expect-error visible activation cannot allocate a different wallet later.
  wallet: { kind: 'server_allocated' },
  presentation: validOutlineOverlayPresentation,
};

// @ts-expect-error outline_overlay cannot carry iframe_button-only styling.
export const invalidMixedOutlinePresentation: RegistrationActivationButtonPresentation = {
  kind: 'outline_overlay',
  label: 'Create with Passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
  iframeVisualStyle: {},
};

// @ts-expect-error iframe_button requires its visual style branch and shadow padding.
export const invalidIncompleteIframeButtonPresentation: RegistrationActivationButtonPresentation = {
  kind: 'iframe_button',
  label: 'Create with Passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
};

// @ts-expect-error activation surfaces require an explicit presentation contract.
export const invalidActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  options: {},
};

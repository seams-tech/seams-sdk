import type {
  CreatePasskeyRegistrationActivationSurfaceArgs,
  RegistrationActivationButtonPresentation,
} from './publicApi/types';

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
  options: {},
};

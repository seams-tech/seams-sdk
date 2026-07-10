import type {
  CreatePasskeyRegistrationActivationSurfaceArgs,
  RegistrationActivationButtonPresentation,
} from './publicApi/types';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type {
  ActivatedPreparedIframePasskeyRegistration,
  PreparedIframePasskeyRegistration,
  RegistrationActivationWebAuthnPromptOwner,
} from './SeamsWeb';
import type { ReservedRegistrationWebAuthnPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import type { RegistrationActivationMessageIdentity } from './publicApi/types';

export const validOutlineOverlayPresentation: RegistrationActivationButtonPresentation = {
  kind: 'outline_overlay',
  label: 'Create with Passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
};

export const validActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  presentation: validOutlineOverlayPresentation,
};

// @ts-expect-error activation surfaces require the displayed provided wallet ID.
export const missingWalletActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  presentation: validOutlineOverlayPresentation,
};

export const serverAllocatedActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs =
  {
    // @ts-expect-error visible activation cannot allocate a different wallet later.
    wallet: { kind: 'server_allocated' },
    presentation: validOutlineOverlayPresentation,
  };

export const invalidMixedOutlinePresentation: RegistrationActivationButtonPresentation = {
  kind: 'outline_overlay',
  label: 'Create with Passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
  // @ts-expect-error public outline overlays cannot style wallet-origin DOM.
  iframeVisualStyle: {},
};

export const invalidIncompleteIframeButtonPresentation: RegistrationActivationButtonPresentation = {
  // @ts-expect-error iframe_button is internal and unavailable through the public API.
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

declare const preparedRegistration: PreparedIframePasskeyRegistration;
declare const activationIdentity: RegistrationActivationMessageIdentity;
declare const activationReservation: ReservedRegistrationWebAuthnPrompt<RegistrationActivationWebAuthnPromptOwner>;
declare const activationCancellation: { kind: 'abort_signal'; signal: AbortSignal };

// @ts-expect-error Activated registration values can only be created by the lifecycle builder.
const rawActivatedRegistration: ActivatedPreparedIframePasskeyRegistration = {
  kind: 'activated_prepared_iframe_passkey_registration_v1',
  prepared: preparedRegistration,
  activation: { identity: activationIdentity, activatedAtMs: 1_900_000_000_000 },
  reservation: activationReservation,
  cancellation: activationCancellation,
};
void rawActivatedRegistration;

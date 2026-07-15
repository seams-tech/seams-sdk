import type {
  CreatePasskeyRegistrationActivationSurfaceArgs,
  RegistrationActivationButtonPresentation,
} from './publicApi/types';
import {
  walletIdFromString,
  type RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import type {
  ActivatedPreparedIframePasskeyRegistration,
  PreparedIframePasskeyRegistration,
  RegistrationActivationWebAuthnPromptOwner,
} from './SeamsWeb';
import type { ReservedRegistrationWebAuthnPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import type { RegistrationActivationMessageIdentity } from './publicApi/types';
import type { RegistrationActivationRecord } from './walletIframe/host/handlers/near';
import type {
  PreparedPasskeyRegistrationPrecompute,
  WalletRegistrationPrecomputeHandle,
} from './operations/registration/registration';

export const validOutlineOverlayPresentation: RegistrationActivationButtonPresentation = {
  kind: 'outline_overlay',
  label: 'Create with Passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
};

const validActivationSignerSelection: RegistrationSignerSetSelection = {
  kind: 'signer_set',
  signers: [
    {
      kind: 'near_ed25519',
      accountProvisioning: {
        kind: 'implicit_account',
        accountIdSource: 'ed25519_public_key',
      },
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  ],
};

export const validActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  signerSelection: validActivationSignerSelection,
  presentation: validOutlineOverlayPresentation,
};

// @ts-expect-error activation surfaces require the displayed provided wallet ID.
export const missingWalletActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs = {
  signerSelection: validActivationSignerSelection,
  presentation: validOutlineOverlayPresentation,
};

export const serverAllocatedActivationSurfaceArgs: CreatePasskeyRegistrationActivationSurfaceArgs =
  {
    // @ts-expect-error visible activation cannot allocate a different wallet later.
    wallet: { kind: 'server_allocated' },
    signerSelection: validActivationSignerSelection,
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
  signerSelection: validActivationSignerSelection,
  options: {},
};

declare const preparedRegistration: PreparedIframePasskeyRegistration;
declare const activationIdentity: RegistrationActivationMessageIdentity;
declare const activationReservation: ReservedRegistrationWebAuthnPrompt<RegistrationActivationWebAuthnPromptOwner>;
declare const activationCancellation: { kind: 'abort_signal'; signal: AbortSignal };
declare const preparingRecord: Extract<RegistrationActivationRecord, { kind: 'preparing' }>;
declare const readyRecord: Extract<RegistrationActivationRecord, { kind: 'ready' }>;

// @ts-expect-error Prepared registration scope is immutable after precompute.
preparedRegistration.walletId = 'mutated-wallet';
// @ts-expect-error Prepared registration signer scope is immutable after precompute.
preparedRegistration.registration.signerSelection.signers = [];

// @ts-expect-error Preparing records cannot enter the activated continuation.
const preparingAsActivatedRegistration: ActivatedPreparedIframePasskeyRegistration =
  preparingRecord;
void preparingAsActivatedRegistration;

// @ts-expect-error Ready records cannot enter the activated continuation without the builder.
const readyAsActivatedRegistration: ActivatedPreparedIframePasskeyRegistration = readyRecord;
void readyAsActivatedRegistration;

const { reservation: omittedReadyReservation, ...readyWithoutReservation } = readyRecord;
void omittedReadyReservation;
// @ts-expect-error Ready records require their WebAuthn prompt reservation.
const invalidReadyWithoutReservation: typeof readyRecord = readyWithoutReservation;
void invalidReadyWithoutReservation;

type ActivationReservation = (typeof readyRecord)['reservation'];
declare const reservationFields: Omit<ActivationReservation, 'owner'>;
const modalReservation = {
  ...reservationFields,
  owner: { kind: 'registration_modal', requestId: activationIdentity.requestId },
} as const;
// @ts-expect-error Activation records reject modal prompt owners.
const invalidModalActivationReservation: ActivationReservation = modalReservation;
void invalidModalActivationReservation;

const walletRequestReservation = {
  ...reservationFields,
  owner: {
    kind: 'wallet_request',
    requestId: activationIdentity.requestId,
    operation: 'registration',
  },
} as const;
// @ts-expect-error Activation records reject generic wallet request prompt owners.
const invalidWalletRequestActivationReservation: ActivationReservation = walletRequestReservation;
void invalidWalletRequestActivationReservation;

// @ts-expect-error Activated registration values can only be created by the lifecycle builder.
const rawActivatedRegistration: ActivatedPreparedIframePasskeyRegistration = {
  kind: 'activated_prepared_iframe_passkey_registration_v1',
  prepared: preparedRegistration,
  activation: { identity: activationIdentity, activatedAtMs: 1_900_000_000_000 },
  reservation: activationReservation,
  cancellation: activationCancellation,
};
void rawActivatedRegistration;

declare const activatedRegistration: ActivatedPreparedIframePasskeyRegistration;
// @ts-expect-error Activated message identity is immutable after activation.
activatedRegistration.activation.identity.requestId = activationIdentity.requestId;
// @ts-expect-error Activated reservation ownership is immutable after activation.
activatedRegistration.reservation.owner = activationReservation.owner;

// @ts-expect-error Precompute handles are opaque lifecycle capabilities.
const rawPrecomputeHandle: WalletRegistrationPrecomputeHandle = {
  kind: 'wallet_registration_precompute_handle_v1',
  handleId: 'forged-handle',
  scope: {
    authMethodKind: 'passkey',
    walletScopeKey: 'provided:frost-fjord-rgcmpa',
    authorityScopeKey: 'passkey:wallet.example.localhost',
    signerSetScopeKey: 'near_ed25519',
  },
};
void rawPrecomputeHandle;

// @ts-expect-error Prepared receipts are minted only after the server intent is verified.
const rawPreparedPrecompute: PreparedPasskeyRegistrationPrecompute = {
  kind: 'prepared_passkey_registration_precompute_v1',
  handle: rawPrecomputeHandle,
  walletId: 'frost-fjord-rgcmpa',
  registrationIntentDigestB64u: 'forged-digest',
};
void rawPreparedPrecompute;

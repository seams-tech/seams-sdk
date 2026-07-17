import type {
  RegistrationActivationButtonPresentation,
  RegistrationActivationId,
  WalletIframeRequestId,
  WalletIframeSurfaceId,
} from '@/SeamsWeb/publicApi/types';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  anchoredRegistrationActivationSurface,
  modalDeviceLinkQrSurface,
  modalRecoveryCodesSurface,
  modalRegistrationConfirmSurface,
  modalTransactionConfirmSurface,
  passkeyRegistrationPreparationReceipt,
  registrationActivationTargetRectFromBoundary,
  walletIframeConnectionIdFromBoundary,
  type AnchoredRegistrationActivationSurface,
  type HiddenWalletIframeSurface,
  type ModalRegistrationConfirmSurface,
  type ModalTransactionConfirmSurface,
  type RegistrationActivationSurfaceIdentity,
  type RequestSurfaceIdentity,
  type WalletIframeSurface,
} from './domain';

declare const surfaceId: WalletIframeSurfaceId;
declare const requestId: WalletIframeRequestId;
declare const activationId: RegistrationActivationId;

const connectionId = walletIframeConnectionIdFromBoundary('connection-1');
const requestIdentity: RequestSurfaceIdentity = {
  kind: 'request_surface_identity_v1',
  surfaceId,
  requestId,
};
const activationIdentity: RegistrationActivationSurfaceIdentity = {
  kind: 'registration_activation_surface_identity_v1',
  surfaceId,
  requestId,
  activationId,
};
const preparation = passkeyRegistrationPreparationReceipt(Date.now() + 60_000);
const presentation: RegistrationActivationButtonPresentation = {
  kind: 'outline_overlay',
  label: 'Create passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey',
};
const placement = {
  kind: 'interactive',
  targetRect: registrationActivationTargetRectFromBoundary({
    top: 0,
    left: 0,
    width: 120,
    height: 48,
  }),
} as const;

anchoredRegistrationActivationSurface({
  connectionId,
  identity: activationIdentity,
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  preparation,
  presentation,
  placement,
  focusOwner: { kind: 'outside' },
});

modalRegistrationConfirmSurface({ connectionId, identity: requestIdentity, preparation });
modalTransactionConfirmSurface({
  connectionId,
  identity: requestIdentity,
});
modalRecoveryCodesSurface({
  connectionId,
  identity: requestIdentity,
  operation: 'show',
});
modalDeviceLinkQrSurface({ connectionId, identity: requestIdentity });

// @ts-expect-error Hidden surfaces cannot carry request ownership.
const hiddenWithIdentity: HiddenWalletIframeSurface = { kind: 'hidden', identity: requestIdentity };
void hiddenWithIdentity;

// @ts-expect-error Registration activation identity requires activationId.
const activationIdentityWithoutActivationId: RegistrationActivationSurfaceIdentity = {
  kind: 'registration_activation_surface_identity_v1',
  surfaceId,
  requestId,
};
void activationIdentityWithoutActivationId;

const anchoredWithAllocatedWallet: AnchoredRegistrationActivationSurface = {
  kind: 'anchored_registration_activation',
  connectionId,
  identity: activationIdentity,
  // @ts-expect-error Anchored registration requires a provided wallet.
  wallet: { kind: 'server_allocated_resolved', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  preparation,
  presentation,
  placement,
  focusOwner: { kind: 'outside' },
};
void anchoredWithAllocatedWallet;

// @ts-expect-error Anchored registration cannot exist without a preparation receipt.
const anchoredWithoutPreparation: AnchoredRegistrationActivationSurface = {
  kind: 'anchored_registration_activation',
  connectionId,
  identity: activationIdentity,
  wallet: { kind: 'provided', walletId: walletIdFromString('frost-fjord-rgcmpa') },
  presentation,
  placement,
  focusOwner: { kind: 'outside' },
};
void anchoredWithoutPreparation;

// @ts-expect-error Registration modals require a preparation receipt.
const modalRegistrationWithoutPreparation: ModalRegistrationConfirmSurface = {
  kind: 'modal_registration_confirm',
  connectionId,
  identity: requestIdentity,
  userActivation: 'wallet_confirm_button_required',
};
void modalRegistrationWithoutPreparation;

const surfaceWithChallenge: WalletIframeSurface = {
  kind: 'modal_registration_confirm',
  connectionId,
  identity: requestIdentity,
  preparation,
  userActivation: 'wallet_confirm_button_required',
  // @ts-expect-error App-origin surface state cannot contain WebAuthn challenge material.
  challengeB64u: 'secret-challenge',
};
void surfaceWithChallenge;

const surfaceWithIndependentExpiry: ModalRegistrationConfirmSurface = {
  kind: 'modal_registration_confirm',
  connectionId,
  identity: requestIdentity,
  preparation,
  userActivation: 'wallet_confirm_button_required',
  // @ts-expect-error Surface expiry is authoritative only inside the preparation receipt.
  expiresAtMs: Date.now() + 60_000,
};
void surfaceWithIndependentExpiry;

const transactionWithoutRequestId: ModalTransactionConfirmSurface = {
  kind: 'modal_transaction_confirm',
  connectionId,
  // @ts-expect-error Transaction modal identity requires requestId.
  identity: { kind: 'request_surface_identity_v1', surfaceId },
  userActivation: 'wallet_confirm_button_required',
};
void transactionWithoutRequestId;

const incompatibleSpread = { ...requestIdentity, activationId };
// @ts-expect-error Broad spread cannot turn request identity into activation identity.
const invalidSpreadIdentity: RegistrationActivationSurfaceIdentity = incompatibleSpread;
void invalidSpreadIdentity;

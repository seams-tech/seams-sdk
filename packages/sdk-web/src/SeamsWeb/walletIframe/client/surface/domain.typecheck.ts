import type {
  WalletIframeRequestId,
  WalletIframeSurfaceId,
} from '@/SeamsWeb/publicApi/types';
import {
  modalDeviceLinkQrSurface,
  modalRecoveryCodesSurface,
  modalRegistrationConfirmSurface,
  modalTransactionConfirmSurface,
  passkeyRegistrationPreparationReceipt,
  walletIframeConnectionIdFromBoundary,
  type HiddenWalletIframeSurface,
  type ModalRegistrationConfirmSurface,
  type ModalTransactionConfirmSurface,
  type RequestSurfaceIdentity,
  type WalletIframeSurface,
} from './domain';

declare const surfaceId: WalletIframeSurfaceId;
declare const requestId: WalletIframeRequestId;

const connectionId = walletIframeConnectionIdFromBoundary('connection-1');
const requestIdentity: RequestSurfaceIdentity = {
  kind: 'request_surface_identity_v1',
  surfaceId,
  requestId,
};
const preparation = passkeyRegistrationPreparationReceipt(Date.now() + 60_000);

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

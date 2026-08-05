import type {
  WalletIframeRequestId,
  WalletIframeSurfaceId,
} from '@/SeamsWeb/publicApi/types';
import {
  modalAuthMenuSurface,
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
import {
  hostedAuthMenuSessionIdFromBoundary,
  type HostedAuthMenuSessionId,
} from '../../shared/messages';

declare const surfaceId: WalletIframeSurfaceId;
declare const requestId: WalletIframeRequestId;

const connectionId = walletIframeConnectionIdFromBoundary('connection-1');
const requestIdentity: RequestSurfaceIdentity = {
  kind: 'request_surface_identity_v1',
  surfaceId,
  requestId,
};
const preparation = passkeyRegistrationPreparationReceipt(Date.now() + 60_000);
const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-1');
if (!authMenuSessionId) throw new Error('auth menu session id fixture is invalid');

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
modalAuthMenuSurface({ connectionId, identity: requestIdentity, authMenuSessionId });

declare const exactAuthMenuSessionId: HostedAuthMenuSessionId;
const authMenuSurface: WalletIframeSurface = {
  kind: 'modal_auth_menu',
  connectionId,
  identity: requestIdentity,
  authMenuSessionId: exactAuthMenuSessionId,
};
void authMenuSurface;

const authMenuSurfaceWithRawSession: WalletIframeSurface = {
  kind: 'modal_auth_menu',
  connectionId,
  identity: requestIdentity,
  // @ts-expect-error Auth-menu surfaces require the exact branded session id.
  authMenuSessionId: 'auth-menu-raw',
};
void authMenuSurfaceWithRawSession;

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

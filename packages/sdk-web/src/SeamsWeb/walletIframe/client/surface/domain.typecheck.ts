import type { WalletIframeRequestId, WalletIframeSurfaceId } from '@/SeamsWeb/publicApi/types';
import {
  modalAuthMenuSurface,
  modalDeviceLinkQrSurface,
  modalRecoveryCodesSurface,
  modalRegistrationConfirmSurface,
  modalTransactionConfirmSurface,
  authMenuWalletIframeSurfacePresentation,
  drawerWalletIframeSurfacePresentation,
  modalWalletIframeSurfacePresentation,
  passkeyRegistrationPreparationReceipt,
  trustedWalletIframeSurfaceMeasurementFromWire,
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
import type { WalletIframeSurfaceMeasurement } from '../../shared/messages';
import type { WalletIframeDrawerGeometry, WalletIframeModalGeometry } from './geometry';
import type { WalletIframeSurfaceRenderMode } from './renderer';

declare const surfaceId: WalletIframeSurfaceId;
declare const requestId: WalletIframeRequestId;

const connectionId = walletIframeConnectionIdFromBoundary('connection-1');
const requestIdentity: RequestSurfaceIdentity = {
  kind: 'request_surface_identity_v1',
  surfaceId,
  requestId,
};
const preparation = passkeyRegistrationPreparationReceipt(Date.now() + 60_000);
const modalPresentation = modalWalletIframeSurfacePresentation('Confirm');
const drawerPresentation = drawerWalletIframeSurfacePresentation('Confirm');
const authMenuPresentation = authMenuWalletIframeSurfacePresentation('Sign in');
const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-1');
if (!authMenuSessionId) throw new Error('auth menu session id fixture is invalid');

modalRegistrationConfirmSurface({
  connectionId,
  identity: requestIdentity,
  presentation: modalPresentation,
  preparation,
});
modalTransactionConfirmSurface({
  connectionId,
  identity: requestIdentity,
  presentation: drawerPresentation,
});
modalRecoveryCodesSurface({
  connectionId,
  identity: requestIdentity,
  presentation: modalPresentation,
  operation: 'show',
});
modalDeviceLinkQrSurface({
  connectionId,
  identity: requestIdentity,
  presentation: modalPresentation,
});
modalAuthMenuSurface({
  connectionId,
  identity: requestIdentity,
  presentation: authMenuPresentation,
  authMenuSessionId,
});

declare const exactAuthMenuSessionId: HostedAuthMenuSessionId;
const authMenuSurface: WalletIframeSurface = {
  kind: 'modal_auth_menu',
  connectionId,
  identity: requestIdentity,
  presentation: authMenuPresentation,
  authMenuSessionId: exactAuthMenuSessionId,
};
void authMenuSurface;

declare const measurement: WalletIframeSurfaceMeasurement;
const trustedMeasurement = trustedWalletIframeSurfaceMeasurementFromWire({
  connectionId,
  identity: requestIdentity,
  measurement,
});
void trustedMeasurement;

const authMenuSurfaceWithRawSession: WalletIframeSurface = {
  kind: 'modal_auth_menu',
  connectionId,
  identity: requestIdentity,
  presentation: authMenuPresentation,
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
  presentation: modalPresentation,
  userActivation: 'wallet_confirm_button_required',
};
void modalRegistrationWithoutPreparation;

const surfaceWithChallenge: WalletIframeSurface = {
  kind: 'modal_registration_confirm',
  connectionId,
  identity: requestIdentity,
  presentation: modalPresentation,
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
  presentation: modalPresentation,
  preparation,
  userActivation: 'wallet_confirm_button_required',
  // @ts-expect-error Surface expiry is authoritative only inside the preparation receipt.
  expiresAtMs: Date.now() + 60_000,
};
void surfaceWithIndependentExpiry;

const transactionWithoutRequestId: ModalTransactionConfirmSurface = {
  kind: 'modal_transaction_confirm',
  connectionId,
  presentation: modalPresentation,
  // @ts-expect-error Transaction modal identity requires requestId.
  identity: { kind: 'request_surface_identity_v1', surfaceId },
  userActivation: 'wallet_confirm_button_required',
};
void transactionWithoutRequestId;

const modalGeometry: WalletIframeModalGeometry = {
  kind: 'centered_modal',
  widthCssPx: 360,
  heightCssPx: 320,
  topCssPx: 224,
  leftCssPx: 332,
};
const drawerGeometry: WalletIframeDrawerGeometry = {
  kind: 'bottom_drawer',
  edge: 'bottom',
  widthCssPx: 320,
  heightCssPx: 320,
  topCssPx: 432,
  leftCssPx: 352,
};

const rightEdgeDrawerGeometry: WalletIframeDrawerGeometry = {
  kind: 'bottom_drawer',
  // @ts-expect-error Right-edge drawers are no longer part of the surface contract.
  edge: 'right',
  widthCssPx: 320,
  heightCssPx: 320,
  topCssPx: 432,
  leftCssPx: 352,
};
void rightEdgeDrawerGeometry;

const validModalRenderMode: WalletIframeSurfaceRenderMode = {
  kind: 'compact_request_modal',
  presentation: modalPresentation,
  geometry: modalGeometry,
  focusTrap: true,
  identity: requestIdentity,
};
void validModalRenderMode;

const validDrawerRenderMode: WalletIframeSurfaceRenderMode = {
  kind: 'compact_request_drawer',
  presentation: drawerPresentation,
  geometry: drawerGeometry,
  focusTrap: true,
  identity: requestIdentity,
};
void validDrawerRenderMode;

const drawerInModalRenderMode: WalletIframeSurfaceRenderMode = {
  kind: 'compact_request_modal',
  // @ts-expect-error Modal render modes reject drawer presentation branches.
  presentation: drawerPresentation,
  // @ts-expect-error Modal render modes reject drawer geometry branches.
  geometry: drawerGeometry,
  focusTrap: true,
  identity: requestIdentity,
};
void drawerInModalRenderMode;

const modalInDrawerRenderMode: WalletIframeSurfaceRenderMode = {
  kind: 'compact_request_drawer',
  // @ts-expect-error Drawer render modes reject centered-modal presentation branches.
  presentation: modalPresentation,
  // @ts-expect-error Drawer render modes reject centered-modal geometry branches.
  geometry: modalGeometry,
  focusTrap: true,
  identity: requestIdentity,
};
void modalInDrawerRenderMode;

const invalidAuthMenuRenderMode: WalletIframeSurfaceRenderMode = {
  kind: 'compact_auth_menu',
  presentation: authMenuPresentation,
  // @ts-expect-error Auth-menu render modes require modal geometry.
  geometry: drawerGeometry,
  focusTrap: true,
  identity: requestIdentity,
};
void invalidAuthMenuRenderMode;

const hiddenWithRenderIdentity: WalletIframeSurfaceRenderMode = {
  kind: 'hidden',
  // @ts-expect-error Hidden render modes carry no identity.
  identity: requestIdentity,
};
void hiddenWithRenderIdentity;

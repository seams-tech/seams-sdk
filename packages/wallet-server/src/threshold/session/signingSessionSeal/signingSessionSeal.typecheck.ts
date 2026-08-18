import type { EcdsaKeyHandle } from '../../../core/keyMaterialBrands';
import type {
  SigningSessionSealEcdsaThresholdSessionRecord,
  SigningSessionSealLinkedDeviceWalletSessionRecord,
} from './signingSessionSeal.types';

declare const keyHandle: EcdsaKeyHandle;

const ownerThresholdSession: SigningSessionSealEcdsaThresholdSessionRecord = {
  kind: 'owner_threshold_session',
  curve: 'ecdsa',
  thresholdSessionId: 'threshold-session',
  userId: 'wallet',
  expiresAtMs: 1,
  relayerKeyId: 'relayer',
  participantIds: [1, 2],
  keyHandle,
};
void ownerThresholdSession;

const linkedDeviceWalletSession: SigningSessionSealLinkedDeviceWalletSessionRecord = {
  kind: 'linked_device_wallet_session',
  walletSessionId: 'wallet-session',
  userId: 'wallet',
  deviceId: 'device',
  enrollmentId: 'enrollment',
  expiresAtMs: 1,
  remainingUses: 1,
};
void linkedDeviceWalletSession;

const linkedDeviceSessionWithCurve: SigningSessionSealLinkedDeviceWalletSessionRecord = {
  kind: 'linked_device_wallet_session',
  // @ts-expect-error Linked-device Wallet Sessions are not curves.
  curve: 'ecdsa',
  walletSessionId: 'wallet-session',
  userId: 'wallet',
  deviceId: 'device',
  enrollmentId: 'enrollment',
  expiresAtMs: 1,
  remainingUses: 1,
};
void linkedDeviceSessionWithCurve;

// @ts-expect-error Linked-device Wallet Sessions require a concrete remaining-use budget.
const linkedDeviceSessionWithoutBudget: SigningSessionSealLinkedDeviceWalletSessionRecord = {
  kind: 'linked_device_wallet_session',
  walletSessionId: 'wallet-session',
  userId: 'wallet',
  deviceId: 'device',
  enrollmentId: 'enrollment',
  expiresAtMs: 1,
};
void linkedDeviceSessionWithoutBudget;

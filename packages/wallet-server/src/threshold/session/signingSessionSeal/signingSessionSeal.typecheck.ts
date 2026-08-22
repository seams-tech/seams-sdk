import type { EcdsaKeyHandle } from '../../../core/keyMaterialBrands';
import type { SigningSessionSealEcdsaThresholdSessionRecord } from './signingSessionSeal.types';

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

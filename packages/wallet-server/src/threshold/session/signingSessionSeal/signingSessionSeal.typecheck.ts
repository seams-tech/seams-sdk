import type { SigningSessionSealEcdsaThresholdSessionRecord } from './signingSessionSeal.types';

const ownerThresholdSession: SigningSessionSealEcdsaThresholdSessionRecord = {
  kind: 'exact_wallet_session_operation_credential',
  curve: 'ecdsa',
  thresholdSessionId: 'threshold-session',
  userId: 'wallet',
  expiresAtMs: 1,
};
void ownerThresholdSession;

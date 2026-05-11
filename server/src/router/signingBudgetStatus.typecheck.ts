import type {
  EcdsaWalletSigningBudgetStatusRequest,
  Ed25519WalletSigningBudgetStatusRequest,
  VerifiedEcdsaThresholdSessionAuth,
  VerifiedEd25519ThresholdSessionAuth,
} from './signingBudgetStatus';

const ecdsaAuth = {
  kind: 'threshold_session',
  curve: 'ecdsa',
  thresholdSessionId: 'threshold-session-ecdsa',
  walletSigningSessionId: 'wallet-signing-session-ecdsa',
  userId: 'wallet-ecdsa',
  rpId: 'example.localhost',
  relayerKeyId: 'ecdsa-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
} satisfies VerifiedEcdsaThresholdSessionAuth;

const ed25519Auth = {
  kind: 'threshold_session',
  curve: 'ed25519',
  thresholdSessionId: 'threshold-session-ed25519',
  walletSigningSessionId: 'wallet-signing-session-ed25519',
  userId: 'wallet-ed25519',
  rpId: 'example.localhost',
  relayerKeyId: 'ed25519-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  ed25519RelayerKeyId: 'ed25519-relayer',
} satisfies VerifiedEd25519ThresholdSessionAuth;

const validEcdsaRequest: EcdsaWalletSigningBudgetStatusRequest = {
  kind: 'ecdsa_wallet_budget_status',
  auth: ecdsaAuth,
  thresholdSessionId: ecdsaAuth.thresholdSessionId,
  walletSigningSessionId: ecdsaAuth.walletSigningSessionId,
  ecdsaThresholdKeyId: ecdsaAuth.ecdsaThresholdKeyId,
};
void validEcdsaRequest;

const invalidEcdsaRequest: EcdsaWalletSigningBudgetStatusRequest = {
  kind: 'ecdsa_wallet_budget_status',
  auth: ecdsaAuth,
  thresholdSessionId: ecdsaAuth.thresholdSessionId,
  walletSigningSessionId: ecdsaAuth.walletSigningSessionId,
  ecdsaThresholdKeyId: ecdsaAuth.ecdsaThresholdKeyId,
  // @ts-expect-error ECDSA request must not carry Ed25519 relayer material
  ed25519RelayerKeyId: 'ed25519-relayer',
};
void invalidEcdsaRequest;

const invalidEd25519Request: Ed25519WalletSigningBudgetStatusRequest = {
  kind: 'ed25519_wallet_budget_status',
  auth: ed25519Auth,
  thresholdSessionId: ed25519Auth.thresholdSessionId,
  walletSigningSessionId: ed25519Auth.walletSigningSessionId,
  ed25519RelayerKeyId: ed25519Auth.ed25519RelayerKeyId,
  // @ts-expect-error Ed25519 request must not carry ECDSA threshold-key material
  ecdsaThresholdKeyId: 'ecdsa-key-1',
};
void invalidEd25519Request;

export {};

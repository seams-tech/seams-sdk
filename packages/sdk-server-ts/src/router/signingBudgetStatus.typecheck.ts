import type {
  EcdsaWalletSigningBudgetStatusRequest,
  Ed25519WalletSigningBudgetStatusRequest,
} from './signingBudgetStatus';
import type {
  VerifiedEcdsaWalletSessionAuth,
  VerifiedEd25519WalletSessionAuth,
} from './verifiedWalletSessionAuth';

const ecdsaAuth = {
  kind: 'wallet_session',
  curve: 'ecdsa',
  thresholdSessionId: 'threshold-session-ecdsa',
  signingGrantId: 'signing-grant-ecdsa',
  userId: 'wallet-ecdsa',
  rpId: 'example.localhost',
  relayerKeyId: 'ecdsa-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  keyHandle: 'ehss-key-1',
} satisfies VerifiedEcdsaWalletSessionAuth;

const ed25519Auth = {
  kind: 'wallet_session',
  curve: 'ed25519',
  thresholdSessionId: 'threshold-session-ed25519',
  signingGrantId: 'signing-grant-ed25519',
  userId: 'wallet-ed25519',
  rpId: 'example.localhost',
  relayerKeyId: 'ed25519-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  ed25519RelayerKeyId: 'ed25519-relayer',
} satisfies VerifiedEd25519WalletSessionAuth;

const validEcdsaRequest: EcdsaWalletSigningBudgetStatusRequest = {
  kind: 'ecdsa_wallet_budget_status',
  auth: ecdsaAuth,
  thresholdSessionId: ecdsaAuth.thresholdSessionId,
  signingGrantId: ecdsaAuth.signingGrantId,
  keyHandle: ecdsaAuth.keyHandle,
};
void validEcdsaRequest;

const invalidEcdsaRequest: EcdsaWalletSigningBudgetStatusRequest = {
  kind: 'ecdsa_wallet_budget_status',
  auth: ecdsaAuth,
  thresholdSessionId: ecdsaAuth.thresholdSessionId,
  signingGrantId: ecdsaAuth.signingGrantId,
  keyHandle: ecdsaAuth.keyHandle,
  // @ts-expect-error ECDSA request must not carry Ed25519 relayer material
  ed25519RelayerKeyId: 'ed25519-relayer',
};
void invalidEcdsaRequest;

const invalidEd25519Request: Ed25519WalletSigningBudgetStatusRequest = {
  kind: 'ed25519_wallet_budget_status',
  auth: ed25519Auth,
  thresholdSessionId: ed25519Auth.thresholdSessionId,
  signingGrantId: ed25519Auth.signingGrantId,
  ed25519RelayerKeyId: ed25519Auth.ed25519RelayerKeyId,
  // @ts-expect-error Ed25519 request must not carry ECDSA key handles
  keyHandle: 'ehss-key-1',
};
void invalidEd25519Request;

const invalidEd25519RequestWithThresholdKeyId: Ed25519WalletSigningBudgetStatusRequest = {
  kind: 'ed25519_wallet_budget_status',
  auth: ed25519Auth,
  thresholdSessionId: ed25519Auth.thresholdSessionId,
  signingGrantId: ed25519Auth.signingGrantId,
  ed25519RelayerKeyId: ed25519Auth.ed25519RelayerKeyId,
  // @ts-expect-error Ed25519 request must not carry ECDSA threshold-key material
  ecdsaThresholdKeyId: 'ecdsa-key-1',
};
void invalidEd25519RequestWithThresholdKeyId;

export {};

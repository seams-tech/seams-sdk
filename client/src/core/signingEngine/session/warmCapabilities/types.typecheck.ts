import type {
  ClaimWarmSessionPrfArgs,
  WarmSessionEcdsaAuthMaterial,
  WarmSessionEd25519AuthMaterial,
  WarmSessionPrfClaim,
} from './types';

void ({
  state: 'warm',
  sessionId: 'session-1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 2,
} satisfies WarmSessionPrfClaim);

void ({
  state: 'unavailable',
  sessionId: 'session-1',
  code: 'worker_error',
} satisfies WarmSessionPrfClaim);

void ({
  state: 'missing',
  sessionId: 'session-1',
} satisfies WarmSessionPrfClaim);

void ({
  state: 'expired',
  sessionId: 'session-1',
} satisfies WarmSessionPrfClaim);

void ({
  state: 'exhausted',
  sessionId: 'session-1',
} satisfies WarmSessionPrfClaim);

// @ts-expect-error warm claims require expiresAtMs
const invalidWarmMissingExpires: WarmSessionPrfClaim = {
  state: 'warm',
  sessionId: 'session-1',
  remainingUses: 2,
};
void invalidWarmMissingExpires;

// @ts-expect-error warm claims require remainingUses
const invalidWarmMissingRemainingUses: WarmSessionPrfClaim = {
  state: 'warm',
  sessionId: 'session-1',
  expiresAtMs: 1_900_000_000_000,
};
void invalidWarmMissingRemainingUses;

// @ts-expect-error unavailable claims require code
const invalidUnavailableMissingCode: WarmSessionPrfClaim = {
  state: 'unavailable',
  sessionId: 'session-1',
};
void invalidUnavailableMissingCode;

// @ts-expect-error missing claims must not carry remainingUses
const invalidMissingWithRemainingUses: WarmSessionPrfClaim = {
  state: 'missing',
  sessionId: 'session-1',
  remainingUses: 1,
};
void invalidMissingWithRemainingUses;

// @ts-expect-error expired claims must not carry expiresAtMs
const invalidExpiredWithExpiresAt: WarmSessionPrfClaim = {
  state: 'expired',
  sessionId: 'session-1',
  expiresAtMs: 1_900_000_000_000,
};
void invalidExpiredWithExpiresAt;

// @ts-expect-error exhausted claims must not carry code
const invalidExhaustedWithCode: WarmSessionPrfClaim = {
  state: 'exhausted',
  sessionId: 'session-1',
  code: 'exhausted',
};
void invalidExhaustedWithCode;

void ({
  kind: 'threshold_only_claim',
  thresholdSessionId: 'session-1',
  errorContext: 'threshold-only claim',
} satisfies ClaimWarmSessionPrfArgs);

void ({
  kind: 'wallet_scoped_ed25519_claim',
  thresholdSessionId: 'session-1',
  errorContext: 'wallet-scoped Ed25519 claim',
  walletId: 'alice.testnet',
  authMethod: 'passkey',
  curve: 'ed25519',
  chain: 'near',
  walletSigningSessionId: 'wallet-session',
} satisfies ClaimWarmSessionPrfArgs);

void ({
  kind: 'wallet_scoped_ecdsa_claim',
  thresholdSessionId: 'session-1',
  errorContext: 'wallet-scoped ECDSA claim',
  walletId: 'alice.testnet',
  authMethod: 'passkey',
  curve: 'ecdsa',
  chain: 'near',
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 1,
    networkSlug: 'ethereum',
  },
  walletSigningSessionId: 'wallet-session',
} satisfies ClaimWarmSessionPrfArgs);

// @ts-expect-error passkey claims require walletSigningSessionId
const invalidPasskeyClaimMissingWalletSession: ClaimWarmSessionPrfArgs = {
  kind: 'wallet_scoped_ed25519_claim',
  thresholdSessionId: 'session-1',
  errorContext: 'wallet-scoped Ed25519 claim',
  walletId: 'alice.testnet',
  authMethod: 'passkey',
  curve: 'ed25519',
  chain: 'near',
};
void invalidPasskeyClaimMissingWalletSession;

// @ts-expect-error wallet-scoped ECDSA claims require chainTarget
const invalidEcdsaClaimMissingChainTarget: ClaimWarmSessionPrfArgs = {
  kind: 'wallet_scoped_ecdsa_claim',
  thresholdSessionId: 'session-1',
  errorContext: 'wallet-scoped ECDSA claim',
  walletId: 'alice.testnet',
  authMethod: 'passkey',
  curve: 'ecdsa',
  chain: 'near',
  walletSigningSessionId: 'wallet-session',
};
void invalidEcdsaClaimMissingChainTarget;

// @ts-expect-error threshold-only claims must not carry wallet-scoped identity
const invalidThresholdOnlyClaimWithWalletSession: ClaimWarmSessionPrfArgs = {
  kind: 'threshold_only_claim',
  thresholdSessionId: 'session-1',
  errorContext: 'threshold-only claim',
  walletSigningSessionId: 'wallet-session',
};
void invalidThresholdOnlyClaimWithWalletSession;

const invalidThresholdOnlyClaimWithCurve: ClaimWarmSessionPrfArgs = {
  kind: 'threshold_only_claim',
  thresholdSessionId: 'session-1',
  errorContext: 'threshold-only claim',
  // @ts-expect-error threshold-only claims must not carry curve material
  curve: 'ecdsa',
};
void invalidThresholdOnlyClaimWithCurve;

void ({
  capability: 'ed25519',
  record: {} as never,
  thresholdSessionAuthToken: 'jwt:ed25519-session',
  thresholdSessionAuthTokenSource: 'ed25519',
} satisfies WarmSessionEd25519AuthMaterial);

void ({
  capability: 'ed25519',
  record: {} as never,
  thresholdSessionAuthTokenSource: 'none',
} satisfies WarmSessionEd25519AuthMaterial);

void ({
  capability: 'ecdsa',
  record: {} as never,
  thresholdSessionAuthToken: 'jwt:ecdsa-session',
  thresholdSessionAuthTokenSource: 'ecdsa',
} satisfies WarmSessionEcdsaAuthMaterial);

void ({
  capability: 'ecdsa',
  record: {} as never,
  thresholdSessionAuthTokenSource: 'none',
} satisfies WarmSessionEcdsaAuthMaterial);

// @ts-expect-error token-bearing Ed25519 auth must carry thresholdSessionAuthToken
const invalidEd25519AuthMissingToken: WarmSessionEd25519AuthMaterial = {
  capability: 'ed25519',
  record: {} as never,
  thresholdSessionAuthTokenSource: 'ed25519',
};
void invalidEd25519AuthMissingToken;

// @ts-expect-error tokenless Ed25519 auth must not carry thresholdSessionAuthToken
const invalidEd25519AuthUnexpectedToken: WarmSessionEd25519AuthMaterial = {
  capability: 'ed25519',
  record: {} as never,
  thresholdSessionAuthToken: 'jwt:ed25519-session',
  thresholdSessionAuthTokenSource: 'none',
};
void invalidEd25519AuthUnexpectedToken;

// @ts-expect-error token-bearing ECDSA auth must carry thresholdSessionAuthToken
const invalidEcdsaAuthMissingToken: WarmSessionEcdsaAuthMaterial = {
  capability: 'ecdsa',
  record: {} as never,
  thresholdSessionAuthTokenSource: 'ecdsa',
};
void invalidEcdsaAuthMissingToken;

// @ts-expect-error tokenless ECDSA auth must not carry thresholdSessionAuthToken
const invalidEcdsaAuthUnexpectedToken: WarmSessionEcdsaAuthMaterial = {
  capability: 'ecdsa',
  record: {} as never,
  thresholdSessionAuthToken: 'jwt:ecdsa-session',
  thresholdSessionAuthTokenSource: 'none',
};
void invalidEcdsaAuthUnexpectedToken;

export {};

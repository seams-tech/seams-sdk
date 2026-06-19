import type {
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealWalletBudgetStatus,
} from '@server/threshold/session/signingSessionSeal/types';

export function buildEcdsaCurveCollisionBudgetStatusFixture(label: string) {
  const nowMs = Date.now();
  const claims = {
    sub: `budget-curve-collision-${label}.testnet`,
    walletId: `budget-curve-collision-${label}.testnet`,
    kind: 'threshold_ecdsa_session_v2',
    sessionId: `threshold-login-curve-collision-${label}`,
    walletSigningSessionId: `wsess-curve-collision-${label}`,
    keyScope: 'evm-family',
    subjectId: `budget-curve-collision-${label}.testnet`,
    chainTarget: {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 5042002,
      networkSlug: 'arc-testnet',
    },
    ecdsaThresholdKeyId: `ecdsa-key-curve-collision-${label}`,
    keyHandle: `key-handle-curve-collision-${label}`,
    relayerKeyId: `ecdsa-relayer-key-curve-collision-${label}`,
    rpId: 'example.localhost',
    thresholdExpiresAtMs: nowMs + 60_000,
    participantIds: [1, 2],
  } as const;

  const baseStatus = (input: {
    curve: 'ecdsa' | 'ed25519';
    thresholdSessionId: string;
    relayerKeyId: string;
    remainingUses: number;
  }) => ({
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    userId: claims.walletId,
    expiresAtMs: nowMs + 60_000,
    remainingUses: input.remainingUses,
    relayerKeyId: input.relayerKeyId,
    rpId: claims.rpId,
    participantIds: [...claims.participantIds],
  });
  const makeThresholdStatus = (input: {
    curve: 'ecdsa' | 'ed25519';
    thresholdSessionId: string;
    relayerKeyId: string;
    remainingUses: number;
  }): SigningSessionSealThresholdSessionStatus => ({
    kind: 'wallet_session',
    ...baseStatus(input),
  });
  const makeWalletBudgetStatus = (input: {
    thresholdSessionId: string;
    walletSigningSessionId: string;
    relayerKeyId: string;
    remainingUses: number;
  }): SigningSessionSealWalletBudgetStatus => ({
    kind: 'wallet_budget',
    walletSigningSessionId: input.walletSigningSessionId,
    ...baseStatus({
      curve: 'ecdsa',
      thresholdSessionId: input.thresholdSessionId,
      relayerKeyId: input.relayerKeyId,
      remainingUses: input.remainingUses,
    }),
  });

  return {
    claims,
    wrongCurveStatus: makeThresholdStatus({
      curve: 'ed25519',
      thresholdSessionId: claims.sessionId,
      relayerKeyId: `ed25519-relayer-key-curve-collision-${label}`,
      remainingUses: 3,
    }),
    ecdsaStatus: makeThresholdStatus({
      curve: 'ecdsa',
      thresholdSessionId: claims.sessionId,
      relayerKeyId: claims.relayerKeyId,
      remainingUses: 3,
    }),
    walletBudgetStatus: makeWalletBudgetStatus({
      thresholdSessionId: claims.sessionId,
      walletSigningSessionId: claims.walletSigningSessionId,
      relayerKeyId: claims.relayerKeyId,
      remainingUses: 2,
    }),
  };
}

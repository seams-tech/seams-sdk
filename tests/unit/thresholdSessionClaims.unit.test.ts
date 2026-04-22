import { expect, test } from '@playwright/test';
import {
  parseThresholdEcdsaSessionClaims,
  parseThresholdEd25519SessionClaims,
} from '@server/core/ThresholdService/validation';

function baseClaims(kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1') {
  return {
    kind,
    sub: 'alice.testnet',
    walletId: 'alice.testnet',
    sessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    relayerKeyId: 'relayer-key-1',
    rpId: 'example.localhost',
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
  };
}

test.describe('threshold session JWT claims', () => {
  test('requires explicit walletId on threshold-ed25519 session tokens', () => {
    const claims = baseClaims('threshold_ed25519_session_v1');

    expect(parseThresholdEd25519SessionClaims(claims)?.walletId).toBe('alice.testnet');
    expect(parseThresholdEd25519SessionClaims({ ...claims, walletId: undefined })).toBeNull();
  });

  test('requires explicit walletId on threshold-ecdsa session tokens', () => {
    const claims = baseClaims('threshold_ecdsa_session_v1');

    expect(parseThresholdEcdsaSessionClaims(claims)?.walletId).toBe('alice.testnet');
    expect(parseThresholdEcdsaSessionClaims({ ...claims, walletId: undefined })).toBeNull();
  });

  test('requires explicit walletSigningSessionId on threshold session tokens', () => {
    expect(
      parseThresholdEd25519SessionClaims({
        ...baseClaims('threshold_ed25519_session_v1'),
        walletSigningSessionId: undefined,
      }),
    ).toBeNull();
    expect(
      parseThresholdEcdsaSessionClaims({
        ...baseClaims('threshold_ecdsa_session_v1'),
        walletSigningSessionId: undefined,
      }),
    ).toBeNull();
  });

  test('rejects threshold-session tokens where JWT sub and walletId disagree', () => {
    expect(
      parseThresholdEd25519SessionClaims({
        ...baseClaims('threshold_ed25519_session_v1'),
        walletId: 'bob.testnet',
      }),
    ).toBeNull();
    expect(
      parseThresholdEcdsaSessionClaims({
        ...baseClaims('threshold_ecdsa_session_v1'),
        walletId: 'bob.testnet',
      }),
    ).toBeNull();
  });
});

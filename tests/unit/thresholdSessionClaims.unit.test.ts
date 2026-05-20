import { expect, test } from '@playwright/test';
import {
  parseThresholdEcdsaSessionClaims,
  parseThresholdEd25519SessionClaims,
} from '@server/core/ThresholdService/validation';
import { signThresholdSessionAuthToken } from '../../server/src/router/commonRouterUtils';
import type { SessionAdapter } from '../../server/src/router/relay';

function baseClaims(kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1') {
  const claims = {
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
  if (kind !== 'threshold_ecdsa_session_v1') return claims;
  return {
    ...claims,
    subjectId: 'wallet-subject-alice',
    chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 5042002 },
    keyHandle: 'ehss-key-test',
  };
}

test.describe('threshold session auth token claims', () => {
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

  test('threshold-ecdsa session tokens require concrete lane identity claims', () => {
    const claims = baseClaims('threshold_ecdsa_session_v1');

    expect(parseThresholdEcdsaSessionClaims(claims)?.subjectId).toBe('wallet-subject-alice');
    expect(parseThresholdEcdsaSessionClaims(claims)?.keyHandle).toBe('ehss-key-test');
    expect(parseThresholdEcdsaSessionClaims({ ...claims, subjectId: undefined })).toBeNull();
    expect(parseThresholdEcdsaSessionClaims({ ...claims, chainTarget: undefined })).toBeNull();
    expect(parseThresholdEcdsaSessionClaims({ ...claims, keyHandle: undefined })).toBeNull();
    expect(
      parseThresholdEcdsaSessionClaims({
        ...claims,
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: '5042002' },
      }),
    ).toBeNull();
  });

  test('signs threshold-ecdsa session tokens with keyHandle when present', async () => {
    let signedPayload: Record<string, unknown> | null = null;
    const session: SessionAdapter = {
      signJwt: async (sub, extra = {}) => {
        signedPayload = { sub, ...extra };
        return 'signed-jwt';
      },
      parse: async () => ({ ok: false }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };
    const result = await signThresholdSessionAuthToken({
      session,
      kind: 'threshold_ecdsa_session_v1',
      userId: 'alice.testnet',
      rpId: 'example.localhost',
      relayerKeyId: 'relayer-key-1',
      sessionInfo: {
        sessionKind: 'jwt',
        sessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
        expiresAtMs: Date.now() + 60_000,
        participantIds: [1, 2],
        subjectId: 'wallet-subject-alice',
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 5042002 },
        keyHandle: 'ehss-key-signed',
      },
      requireJwtErrorMessage: 'jwt required',
      invalidPayloadErrorMessage: 'invalid payload',
    });

    expect(result.ok).toBe(true);
    expect(signedPayload).toEqual(expect.objectContaining({ keyHandle: 'ehss-key-signed' }));
    expect(signedPayload).not.toHaveProperty('ecdsaThresholdKeyId');
    expect(parseThresholdEcdsaSessionClaims(signedPayload)?.keyHandle).toBe('ehss-key-signed');
  });
});

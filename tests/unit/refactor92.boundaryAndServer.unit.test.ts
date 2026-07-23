import { expect, test } from '@playwright/test';
import { SessionService } from '@server/core/SessionService';
import {
  walletSessionFailureCodeFromParseReason,
  walletSessionFailureMessage,
  walletSessionFailureStatus,
} from '@server/router/walletSessionFailure';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseWalletSessionAuthorizationBoundary,
  requireActiveWalletSessionAuthorization,
} from '@/core/signingEngine/session/identity/clientSessionPersistenceState';
import { buildEd25519PasskeySigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import type { SessionParseFailureReason } from '@server/core/sessionValidation';

const NOW_MS = 1_900_000_000_000;
const NOW_SECONDS = Math.floor(NOW_MS / 1_000);
const LANE = buildEd25519PasskeySigningLane({
  walletId: toWalletId('refactor-92-boundary-wallet'),
  nearAccountId: toAccountId('refactor-92.testnet'),
  nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('refactor-92-key'),
  signerSlot: 1,
  auth: {
    kind: 'passkey',
    rpId: toRpId('localhost'),
    credentialIdB64u: 'refactor-92-credential',
  },
  signingGrantId: SigningSessionIds.signingGrant('refactor-92-grant'),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session('refactor-92-session'),
  storageSource: 'login',
});

class FixedNowSessionService extends SessionService {
  override nowSeconds(): number {
    return NOW_SECONDS;
  }
}

function validTokenVerifier(): { valid: true; payload: { sub: string; exp: number } } {
  return { valid: true, payload: { sub: 'wallet', exp: NOW_SECONDS + 1 } };
}

test('Refactor 92 boundary parser classifies equality and elapsed time as expired', () => {
  for (const expiresAtMs of [NOW_MS - 1, NOW_MS]) {
    expect(
      parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'found', identity: LANE.identity, expiresAtMs },
        nowMs: NOW_MS,
      }),
    ).toEqual({
      kind: 'expired',
      walletId: LANE.identity.signer.account.wallet.walletId,
      walletSessionId: LANE.signingGrantId,
      authMethod: 'passkey',
      laneIdentity: LANE.identity,
      expiresAtMs,
      detectedAtMs: NOW_MS,
    });
  }
});

test('Refactor 92 boundary parser admits only a future expiry as active', () => {
  const state = parseWalletSessionAuthorizationBoundary({
    observation: { kind: 'found', identity: LANE.identity, expiresAtMs: NOW_MS + 1 },
    nowMs: NOW_MS,
  });
  if (state.kind !== 'active') throw new Error('Expected active authorization state');
  expect(requireActiveWalletSessionAuthorization(state)).toBe(state);
});

test('Refactor 92 boundary parser keeps missing, unavailable, and invalid distinct', () => {
  expect(
    parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'missing', identity: LANE.identity },
      nowMs: NOW_MS,
    }).kind,
  ).toBe('missing');
  expect(
    parseWalletSessionAuthorizationBoundary({
      observation: {
        kind: 'unavailable',
        identity: LANE.identity,
        reason: 'server_unavailable',
      },
      nowMs: NOW_MS,
    }),
  ).toEqual(expect.objectContaining({ kind: 'unavailable', reason: 'server_unavailable' }));
  expect(
    parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'found', identity: LANE.identity, expiresAtMs: 'invalid' },
      nowMs: NOW_MS,
    }),
  ).toEqual(expect.objectContaining({ kind: 'invalid', reason: 'malformed' }));
});

test('Refactor 92 server parser gives temporal claims exact precedence', async () => {
  const atBoundary = new FixedNowSessionService({
    jwt: {
      verifyToken: validTokenVerifier,
    },
  });
  const expired = await atBoundary.verifyJwt('token');
  expect(expired).toEqual({
    valid: true,
    payload: { sub: 'wallet', exp: NOW_SECONDS + 1 },
  });

  const elapsed = new FixedNowSessionService({
    jwt: {
      verifyToken: verifyElapsedToken,
    },
  });
  expect(await elapsed.verifyJwt('token')).toEqual({ valid: false, reason: 'expired' });
});

test('Refactor 92 maps every parse failure to one exact server code and status', () => {
  const cases: ReadonlyArray<{
    reason: SessionParseFailureReason;
    code: string;
    status: number;
  }> = [
    { reason: 'missing', code: WALLET_SESSION_FAILURE_CODES.missing, status: 401 },
    {
      reason: 'signature_invalid',
      code: WALLET_SESSION_FAILURE_CODES.signatureInvalid,
      status: 401,
    },
    {
      reason: 'claims_invalid',
      code: WALLET_SESSION_FAILURE_CODES.claimsInvalid,
      status: 401,
    },
    { reason: 'not_active', code: WALLET_SESSION_FAILURE_CODES.claimsInvalid, status: 401 },
    { reason: 'expired', code: WALLET_SESSION_FAILURE_CODES.expired, status: 401 },
  ];
  for (const entry of cases) {
    const code = walletSessionFailureCodeFromParseReason(entry.reason);
    expect(code).toBe(entry.code);
    expect(walletSessionFailureStatus(code)).toBe(entry.status);
    expect(walletSessionFailureMessage(code)).not.toEqual('');
  }
});

function verifyElapsedToken(): {
  valid: true;
  payload: { sub: string; exp: number; remainingUses: number };
} {
  return {
    valid: true,
    payload: { sub: 'wallet', exp: NOW_SECONDS, remainingUses: 0 },
  };
}

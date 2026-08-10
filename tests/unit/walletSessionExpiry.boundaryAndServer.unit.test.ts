import { expect, test } from '@playwright/test';
import { SessionService } from '@server/core/SessionService';
import {
  walletSessionFailureCodeFromParseReason,
  walletSessionFailureMessage,
  walletSessionFailureStatus,
} from '@server/router/auth/walletSessionFailure';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseWalletSessionAuthorizationBoundary,
  requireActiveWalletSessionAuthorization,
} from '@/core/signingEngine/session/identity/clientSessionPersistenceState';
import { readClientWalletSessionAuthorization } from '@/core/signingEngine/session/persistence/clientSessionPersistence';
import {
  buildActiveWalletSessionAuthorizationProjection,
  parseWalletSessionAuthorizationProjection,
  walletSessionAuthorizations,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
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
  walletSessionId: SigningSessionIds.walletSession('refactor-92-wallet-session'),
  quotaId: SigningSessionIds.walletSessionQuota('refactor-92-quota'),
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

function walletSessionJwtFixture(expiresAtMs: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      authorizationKind: 'owner_wallet_session',
      walletId: String(LANE.identity.signer.account.wallet.walletId),
      authorizationId: 'refactor-92-authorization',
      walletSessionId: 'refactor-92-wallet-session',
      quotaId: 'refactor-92-quota',
      sid: 'refactor-92-authorization-session',
      thresholdExpiresAtMs: expiresAtMs,
      exp: Math.floor(expiresAtMs / 1_000),
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}

function activeAuthorizationFixture(expiresAtMs: number, authMethod: 'passkey' | 'email_otp') {
  const walletId = LANE.identity.signer.account.wallet.walletId;
  const authorizationSessionId = parseSeamsSessionId('refactor-92-authorization-session');
  const walletSessionId = parseWalletSessionId('refactor-92-wallet-session');
  const authorizationId = parseWalletSessionAuthorizationId('refactor-92-authorization');
  const quotaId = parseMpcWalletSigningQuotaId('refactor-92-quota');
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId,
    authorityDigest: 'refactor-92-authority',
  });
  if (
    !authorizationSessionId.ok ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    !authority
  ) {
    throw new Error('Failed to build Refactor 92 authorization fixture');
  }
  return buildActiveWalletSessionAuthorizationProjection({
    walletId,
    seamsSessionId: authorizationSessionId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: { walletSessionJwt: walletSessionJwtFixture(expiresAtMs) },
    },
    authMethod,
    authority,
    expiresAtMs,
  });
}

test('Refactor 92 boundary parser classifies equality and elapsed time as expired', () => {
  for (const expiresAtMs of [NOW_MS - 1, NOW_MS]) {
    expect(
      parseWalletSessionAuthorizationBoundary({
        observation: {
          kind: 'found',
          source: { kind: 'ed25519', laneIdentity: LANE.identity },
          expiresAtMs,
        },
        nowMs: NOW_MS,
      }),
    ).toEqual({
      kind: 'expired',
      walletId: LANE.identity.signer.account.wallet.walletId,
      walletSessionId: LANE.walletSessionId,
      quotaId: LANE.quotaId,
      authMethod: 'passkey',
      laneIdentity: LANE.identity,
      expiresAtMs,
      detectedAtMs: NOW_MS,
    });
  }
});

test('Refactor 92 boundary parser admits only a future expiry as active', () => {
  const state = parseWalletSessionAuthorizationBoundary({
    observation: {
      kind: 'found',
      source: { kind: 'ed25519', laneIdentity: LANE.identity },
      expiresAtMs: NOW_MS + 1,
    },
    nowMs: NOW_MS,
  });
  if (state.kind !== 'active') throw new Error('Expected active authorization state');
  expect(requireActiveWalletSessionAuthorization(state)).toBe(state);
});

test('Refactor 92 boundary parser keeps missing, unavailable, and invalid distinct', () => {
  expect(
    parseWalletSessionAuthorizationBoundary({
      observation: {
        kind: 'missing',
        source: { kind: 'ed25519', laneIdentity: LANE.identity },
      },
      nowMs: NOW_MS,
    }).kind,
  ).toBe('missing');
  expect(
    parseWalletSessionAuthorizationBoundary({
      observation: {
        kind: 'unavailable',
        source: { kind: 'ed25519', laneIdentity: LANE.identity },
        reason: 'server_unavailable',
      },
      nowMs: NOW_MS,
    }),
  ).toEqual(expect.objectContaining({ kind: 'unavailable', reason: 'server_unavailable' }));
  expect(
    parseWalletSessionAuthorizationBoundary({
      observation: {
        kind: 'found',
        source: { kind: 'ed25519', laneIdentity: LANE.identity },
        expiresAtMs: 'invalid',
      },
      nowMs: NOW_MS,
    }),
  ).toEqual(expect.objectContaining({ kind: 'invalid', reason: 'malformed' }));
});

test('persistence boundary rejects pairwise aliased authorization identities', () => {
  const active = activeAuthorizationFixture(NOW_MS + 1, 'passkey');

  expect(
    parseWalletSessionAuthorizationProjection({
      ...active,
      authorizationId: active.walletSessionId,
    }),
  ).toBeNull();
  expect(
    parseWalletSessionAuthorizationProjection({
      ...active,
      quotaId: active.walletSessionId,
    }),
  ).toBeNull();
});

test('Ed25519 export preflight reads canonical Wallet Session authorization', async () => {
  const originalRead = walletSessionAuthorizations.readActiveForWallet;
  try {
    walletSessionAuthorizations.readActiveForWallet = async () => ({
      kind: 'found',
      projection: activeAuthorizationFixture(NOW_MS + 1, 'passkey'),
    });
    await expect(
      readClientWalletSessionAuthorization({
        kind: 'ed25519',
        laneIdentity: LANE.identity,
        nowMs: NOW_MS,
      }),
    ).resolves.toEqual(expect.objectContaining({ kind: 'active', expiresAtMs: NOW_MS + 1 }));

    walletSessionAuthorizations.readActiveForWallet = async () => ({
      kind: 'found',
      projection: activeAuthorizationFixture(NOW_MS + 1, 'email_otp'),
    });
    await expect(
      readClientWalletSessionAuthorization({
        kind: 'ed25519',
        laneIdentity: LANE.identity,
        nowMs: NOW_MS,
      }),
    ).resolves.toEqual(expect.objectContaining({ kind: 'invalid', reason: 'scope_mismatch' }));
  } finally {
    walletSessionAuthorizations.readActiveForWallet = originalRead;
  }
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

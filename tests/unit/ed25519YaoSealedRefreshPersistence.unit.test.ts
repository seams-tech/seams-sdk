import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
  type PasskeyEd25519YaoSessionPersistencePort,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  authorizeRouterAbEd25519WalletSessionState,
  buildRouterAbEd25519WalletSessionStateFromExactRuntime,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';
import { buildActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { buildPasskeyEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';

const SEALED_RECORD = buildPasskeyEd25519SealedSessionRecordFixture();
const WALLET_ID = SEALED_RECORD.walletId;
const NEAR_ACCOUNT_ID = toAccountId(SEALED_RECORD.ed25519Restore.nearAccountId);
const NEAR_SIGNING_KEY_ID = SEALED_RECORD.ed25519Restore.nearEd25519SigningKeyId;
const THRESHOLD_SESSION_ID = SEALED_RECORD.thresholdSessionIds.ed25519;
const SIGNING_GRANT_ID = SEALED_RECORD.signingGrantId;

type SessionPersistenceCall = { kind: 'hydrate' | 'persist'; input: unknown };

class SessionPersistenceFixture implements PasskeyEd25519YaoSessionPersistencePort {
  readonly calls: SessionPersistenceCall[] = [];

  constructor(private readonly persistResult: WarmSessionSealAndPersistResult) {}

  async hydrateSigningSession(
    input: Parameters<PasskeyEd25519YaoSessionPersistencePort['hydrateSigningSession']>[0],
  ): Promise<void> {
    this.calls.push({ kind: 'hydrate', input });
  }

  async persistSigningSessionSealForThresholdSession(
    input: Parameters<
      PasskeyEd25519YaoSessionPersistencePort['persistSigningSessionSealForThresholdSession']
    >[0],
  ): Promise<WarmSessionSealAndPersistResult> {
    this.calls.push({ kind: 'persist', input });
    return this.persistResult;
  }
}

function sessionPersistenceCallKind(call: SessionPersistenceCall): SessionPersistenceCall['kind'] {
  return call.kind;
}

function buildPasskeyWalletSessionAuthorization(args: {
  expiresAtMs: number;
  walletSessionJwt?: string;
}) {
  const authorizationSessionId = parseSeamsSessionId('seams-session-ed25519-refresh');
  const walletSessionId = parseWalletSessionId('wallet-session-ed25519-refresh');
  const quotaId = parseMpcWalletSigningQuotaId('quota-ed25519-refresh');
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: WALLET_ID,
    authorityDigest: 'authority-digest-ed25519-refresh',
  });
  if (!authorizationSessionId.ok || !walletSessionId.ok || !quotaId.ok || !authority) {
    throw new Error('failed to build Ed25519 Wallet Session authorization fixture');
  }
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: authority.walletId,
    authorizationSessionId: authorizationSessionId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionJwt: args.walletSessionJwt || SEALED_RECORD.ed25519Restore.walletSessionJwt,
    authMethod: 'passkey',
    authority,
    expiresAtMs: args.expiresAtMs,
  });
}

function buildPasskeyYaoWalletSession() {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const currentWalletSessionJwt = `${SEALED_RECORD.ed25519Restore.walletSessionJwt
    .split('.')
    .slice(0, 2)
    .join('.')}.current`;
  const session = buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: currentWalletSessionJwt,
    nowMs: runtime.expiresAtMs - 1,
  });
  return {
    ed25519Restore: buildPasskeyEd25519RestoreMetadata({
      rpId: SEALED_RECORD.ed25519Restore.rpId,
      nearAccountId: SEALED_RECORD.ed25519Restore.nearAccountId,
      nearEd25519SigningKeyId: SEALED_RECORD.ed25519Restore.nearEd25519SigningKeyId,
      relayerKeyId: SEALED_RECORD.ed25519Restore.relayerKeyId,
      participantIds: SEALED_RECORD.ed25519Restore.participantIds,
      runtimePolicyScope: SEALED_RECORD.ed25519Restore.runtimePolicyScope,
      signerSlot: SEALED_RECORD.ed25519Restore.signerSlot,
      routerAbNormalSigning: SEALED_RECORD.ed25519Restore.routerAbNormalSigning,
      credentialIdB64u: SEALED_RECORD.ed25519Restore.credentialIdB64u,
      walletSessionJwt: currentWalletSessionJwt,
    }),
    expiresAtMs: runtime.expiresAtMs,
    walletSessionJwt: currentWalletSessionJwt,
    session,
  };
}

test('persists and verifies a passkey Yao session seal for page refresh', async () => {
  const fixture = buildPasskeyYaoWalletSession();
  const persistence = new SessionPersistenceFixture({
    ok: true,
    sealedSecretB64u: 'sealed-session-refresh-secret',
    remainingUses: 3,
    expiresAtMs: fixture.expiresAtMs,
  });

  await persistPasskeyEd25519YaoSessionForRefresh({
    persistence,
    session: fixture.session,
    prfFirstB64u: 'passkey-prf-first-ed25519-yao-sealed-refresh',
    ed25519Restore: fixture.ed25519Restore,
  });

  expect(persistence.calls.map(sessionPersistenceCallKind)).toEqual(['hydrate', 'persist']);
  expect(persistence.calls[0].input).toMatchObject({
    sessionId: THRESHOLD_SESSION_ID,
    remainingUses: 3,
    transport: {
      curve: 'ed25519',
      authMethod: 'passkey',
      walletId: WALLET_ID,
      signingGrantId: SIGNING_GRANT_ID,
      walletSessionJwt: fixture.walletSessionJwt,
      ed25519Restore: fixture.ed25519Restore,
    },
  });
  expect(persistence.calls[1].input).toMatchObject({
    sessionId: THRESHOLD_SESSION_ID,
    transport: {
      ed25519Restore: fixture.ed25519Restore,
    },
  });
});

test('authorizes Ed25519 normal signing from the correlated Wallet Session projection', () => {
  const fixture = buildPasskeyYaoWalletSession();
  const authorization = buildPasskeyWalletSessionAuthorization({
    expiresAtMs: fixture.expiresAtMs,
    walletSessionJwt: fixture.walletSessionJwt,
  });

  const authorized = authorizeRouterAbEd25519WalletSessionState({
    state: fixture.session,
    authorization,
    nowMs: fixture.expiresAtMs - 1,
  });

  expect(authorized?.walletSessionId).toBe(authorization.walletSessionId);
  expect(authorized?.walletSessionAuthorization).toBe(authorization);
});

test('rejects an Ed25519 Wallet Session projection with a different lifecycle', () => {
  const fixture = buildPasskeyYaoWalletSession();
  const authorization = buildPasskeyWalletSessionAuthorization({
    expiresAtMs: fixture.expiresAtMs + 1,
  });

  expect(
    authorizeRouterAbEd25519WalletSessionState({
      state: fixture.session,
      authorization,
      nowMs: fixture.expiresAtMs - 1,
    }),
  ).toBeNull();
});

test('fails the lifecycle when the durable Yao session seal is unavailable', async () => {
  const fixture = buildPasskeyYaoWalletSession();
  const persistence = new SessionPersistenceFixture({
    ok: false,
    code: 'not_enabled',
    message: 'sealed refresh is disabled',
  });

  await expect(
    persistPasskeyEd25519YaoSessionForRefresh({
      persistence,
      session: fixture.session,
      prfFirstB64u: 'passkey-prf-first-ed25519-yao-sealed-refresh',
      ed25519Restore: fixture.ed25519Restore,
    }),
  ).rejects.toThrow('Ed25519 Yao sealed refresh persistence failed (not_enabled)');
});

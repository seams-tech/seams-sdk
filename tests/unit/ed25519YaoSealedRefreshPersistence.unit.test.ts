import { expect, test } from '@playwright/test';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
  type PasskeyEd25519YaoSessionPersistencePort,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  authorizeRouterAbEd25519WalletSessionState,
  buildPasskeyRouterAbEd25519WalletSessionState,
  buildRouterAbEd25519WalletSessionStateFromExactRuntime,
  rebindRouterAbEd25519WalletSessionStateFromExactRuntime,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';
import { buildActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { RegistrationEstablishedSession } from '@shared/utils/registrationEstablishedSession';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { toAccountId } from '@/core/types/accountIds';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const SEALED_RECORD = buildPasskeyEd25519SealedSessionRecordFixture();
const WALLET_ID = SEALED_RECORD.walletId;
const THRESHOLD_SESSION_ID = SEALED_RECORD.thresholdSessionIds.ed25519;

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
  walletSessionJwt: string;
  authorityDigest?: string;
}) {
  const authorizationSessionId = parseSeamsSessionId(`authorization:${THRESHOLD_SESSION_ID}`);
  const authorizationId = parseWalletSessionAuthorizationId(
    `wallet-session-authorization:${THRESHOLD_SESSION_ID}`,
  );
  const walletSessionId = parseWalletSessionId(`wallet-session:${THRESHOLD_SESSION_ID}`);
  const quotaId = parseMpcWalletSigningQuotaId(`quota:${THRESHOLD_SESSION_ID}`);
  const expectedAuthority = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: WALLET_ID,
    authorityDigest: args.authorityDigest ?? expectedAuthority.authority.authorityDigest,
  });
  if (
    !authorizationSessionId.ok ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    !authority
  ) {
    throw new Error('failed to build Ed25519 Wallet Session authorization fixture');
  }
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: authority.walletId,
    seamsSessionId: authorizationSessionId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: { walletSessionJwt: args.walletSessionJwt },
    },
    authMethod: 'passkey',
    authority,
    expiresAtMs: args.expiresAtMs,
  });
}

function buildPasskeyYaoWalletSession() {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const authorizationFixture = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const currentWalletSessionJwt = `${authorizationFixture.walletSessionTokens.ed25519.walletSessionJwt
    .split('.')
    .slice(0, 2)
    .join('.')}.current`;
  const session = buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: currentWalletSessionJwt,
    authority: authorizationFixture.authority,
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
      materialActivation: SEALED_RECORD.ed25519Restore.materialActivation,
    }),
    expiresAtMs: runtime.expiresAtMs,
    walletSessionJwt: currentWalletSessionJwt,
    session,
  };
}

function buildRegistrationEstablishedPasskeySession(
  args: {
    nearAccountId?: string;
  } = {},
): RegistrationEstablishedSession {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const signingRoot = signingRootScopeFromRuntimePolicyScope(
    SEALED_RECORD.ed25519Restore.runtimePolicyScope,
  );
  const nearAccountId = args.nearAccountId ?? SEALED_RECORD.ed25519Restore.nearAccountId;
  return {
    kind: 'registration_established_wallet_session_v1',
    walletId: WALLET_ID,
    seamsSessionId: authorization.seamsSessionId,
    authorizationId: authorization.authorizationId,
    walletSessionId: authorization.walletSessionId,
    quotaId: authorization.quotaId,
    expiresAtMs: runtime.expiresAtMs,
    remainingUses: runtime.remainingUses,
    tokens: {
      kind: 'near_ed25519',
      ed25519: {
        walletSessionJwt: authorization.walletSessionTokens.ed25519.walletSessionJwt,
        thresholdSessionId: SEALED_RECORD.thresholdSessionIds.ed25519,
        nearAccountId,
        nearEd25519SigningKeyId: SEALED_RECORD.ed25519Restore.nearEd25519SigningKeyId,
        runtimePolicyScope: SEALED_RECORD.ed25519Restore.runtimePolicyScope,
        routerAbNormalSigning: SEALED_RECORD.ed25519Restore.routerAbNormalSigning,
      },
    },
  };
}

function buildPasskeyStateFromRegistrationEstablishedSession(
  registrationEstablishedSession: RegistrationEstablishedSession,
) {
  if (registrationEstablishedSession.tokens.kind !== 'near_ed25519') {
    throw new Error('registration fixture must contain an Ed25519 token');
  }
  const token = registrationEstablishedSession.tokens.ed25519;
  const signingRoot = signingRootScopeFromRuntimePolicyScope(token.runtimePolicyScope);
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: WALLET_ID,
    nearAccountId: token.nearAccountId,
    nearEd25519SigningKeyId: token.nearEd25519SigningKeyId,
    walletSessionId: registrationEstablishedSession.walletSessionId,
    quotaId: registrationEstablishedSession.quotaId,
    thresholdSessionId: token.thresholdSessionId,
    remainingUses: registrationEstablishedSession.remainingUses,
    expiresAtMs: registrationEstablishedSession.expiresAtMs,
    runtimePolicyScope: token.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion || '',
    routerAbNormalSigning: token.routerAbNormalSigning,
    walletSessionJwt: token.walletSessionJwt,
    nowMs: registrationEstablishedSession.expiresAtMs - 1,
  });
  if (!signingWalletSession.ok) {
    throw new Error(`registration fixture session is invalid: ${signingWalletSession.reason}`);
  }
  return buildPasskeyRouterAbEd25519WalletSessionState({
    walletId: WALLET_ID,
    nearAccountId: toAccountId(token.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(token.nearEd25519SigningKeyId),
    signerSlot: SEALED_RECORD.ed25519Restore.signerSlot,
    rpId: toRpId(SEALED_RECORD.ed25519Restore.rpId),
    credentialIdB64u: SEALED_RECORD.ed25519Restore.credentialIdB64u,
    relayerUrl: SEALED_RECORD.relayerUrl,
    authority: buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD).authority,
    signingWalletSession: signingWalletSession.value,
  });
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
    materialActivation: fixture.ed25519Restore.materialActivation,
  });

  expect(persistence.calls.map(sessionPersistenceCallKind)).toEqual(['hydrate', 'persist']);
  expect(persistence.calls[0].input).toMatchObject({
    thresholdSessionId: THRESHOLD_SESSION_ID,
    remainingUses: 3,
    transport: {
      curve: 'ed25519',
      authMethod: 'passkey',
      walletId: WALLET_ID,
      walletSessionJwt: fixture.walletSessionJwt,
      ed25519Restore: fixture.ed25519Restore,
    },
  });
  expect(persistence.calls[1].input).toMatchObject({
    thresholdSessionId: THRESHOLD_SESSION_ID,
    transport: {
      ed25519Restore: fixture.ed25519Restore,
    },
  });
});

test('persists the exact runtime from registration-established Ed25519 authorization', async () => {
  const registrationEstablishedSession = buildRegistrationEstablishedPasskeySession();
  const session = buildPasskeyStateFromRegistrationEstablishedSession(
    registrationEstablishedSession,
  );
  const restore = buildPasskeyEd25519RestoreMetadata({
    rpId: SEALED_RECORD.ed25519Restore.rpId,
    nearAccountId: SEALED_RECORD.ed25519Restore.nearAccountId,
    nearEd25519SigningKeyId: SEALED_RECORD.ed25519Restore.nearEd25519SigningKeyId,
    relayerKeyId: SEALED_RECORD.ed25519Restore.relayerKeyId,
    participantIds: SEALED_RECORD.ed25519Restore.participantIds,
    runtimePolicyScope: SEALED_RECORD.ed25519Restore.runtimePolicyScope,
    signerSlot: SEALED_RECORD.ed25519Restore.signerSlot,
    routerAbNormalSigning: SEALED_RECORD.ed25519Restore.routerAbNormalSigning,
    credentialIdB64u: SEALED_RECORD.ed25519Restore.credentialIdB64u,
    materialActivation: SEALED_RECORD.ed25519Restore.materialActivation,
  });
  const persistence = new SessionPersistenceFixture({
    ok: true,
    sealedSecretB64u: 'registration-established-sealed-secret',
    remainingUses: registrationEstablishedSession.remainingUses,
    expiresAtMs: registrationEstablishedSession.expiresAtMs,
  });

  await persistPasskeyEd25519YaoSessionForRefresh({
    persistence,
    session,
    prfFirstB64u: 'registration-established-prf-first',
    ed25519Restore: restore,
    materialActivation: restore.materialActivation,
  });

  expect(persistence.calls.map(sessionPersistenceCallKind)).toEqual(['hydrate', 'persist']);
  expect(persistence.calls[1].input).toMatchObject({
    thresholdSessionId: SEALED_RECORD.thresholdSessionIds.ed25519,
    transport: { ed25519Restore: restore },
  });

  const foreignRegistrationSession = buildRegistrationEstablishedPasskeySession({
    nearAccountId: 'foreign-near-account.testnet',
  });
  expect(() =>
    buildPasskeyStateFromRegistrationEstablishedSession(foreignRegistrationSession),
  ).toThrow('wallet_binding_mismatch');
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

test('rejects a renewed Ed25519 projection with a hostile authority digest', () => {
  const fixture = buildPasskeyYaoWalletSession();
  const hostileAuthorization = buildPasskeyWalletSessionAuthorization({
    expiresAtMs: fixture.expiresAtMs,
    walletSessionJwt: fixture.walletSessionJwt,
    authorityDigest: 'hostile-ed25519-authority-digest',
  });

  const authorized = authorizeRouterAbEd25519WalletSessionState({
    state: fixture.session,
    authorization: hostileAuthorization,
    nowMs: fixture.expiresAtMs - 1,
  });

  expect(authorized).toBeNull();
});

test('accepts a renewed authorization expiry while retaining the sealed runtime expiry', () => {
  const fixture = buildPasskeyYaoWalletSession();
  const renewedExpiresAtMs = fixture.expiresAtMs + 60_000;
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD, {
    authorizationExpiresAtMs: renewedExpiresAtMs,
  });
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const renewedState = buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: authorization.walletSessionTokens.ed25519.walletSessionJwt,
    authority: authorization.authority,
    nowMs: fixture.expiresAtMs - 1,
  });

  const authorized = authorizeRouterAbEd25519WalletSessionState({
    state: renewedState,
    authorization,
    nowMs: fixture.expiresAtMs - 1,
  });

  expect(authorized).not.toBeNull();
  expect(authorized?.signingWalletSession.expiresAtMs).toBe(fixture.expiresAtMs);
  expect(authorized?.walletSessionAuthorization.expiresAtMs).toBe(renewedExpiresAtMs);
});

test('renews Wallet Session authorization without changing Ed25519 material activation', () => {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const originalAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const renewedAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD, {
    authorizationSessionId: 'authorization:ed25519-renewed',
    walletSessionId: 'wallet-session:ed25519-renewed',
    quotaId: 'quota:ed25519-renewed',
  });
  const originalState = buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: originalAuthorization.walletSessionTokens.ed25519.walletSessionJwt,
    authority: originalAuthorization.authority,
    nowMs: runtime.expiresAtMs - 1,
  });
  const renewedState = buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: renewedAuthorization.walletSessionTokens.ed25519.walletSessionJwt,
    authority: renewedAuthorization.authority,
    nowMs: runtime.expiresAtMs - 1,
  });

  const original = authorizeRouterAbEd25519WalletSessionState({
    state: originalState,
    authorization: originalAuthorization,
    nowMs: runtime.expiresAtMs - 1,
  });
  const renewed = authorizeRouterAbEd25519WalletSessionState({
    state: renewedState,
    authorization: renewedAuthorization,
    nowMs: runtime.expiresAtMs - 1,
  });

  expect(original).not.toBeNull();
  expect(renewed).not.toBeNull();
  expect(renewedAuthorization.walletSessionId).not.toBe(originalAuthorization.walletSessionId);
  expect(renewedAuthorization.seamsSessionId).not.toBe(originalAuthorization.seamsSessionId);
  expect(renewed?.thresholdSessionId).toBe(original?.thresholdSessionId);
  expect(renewed?.remainingUses).toBe(original?.remainingUses);
  expect(renewed?.remainingUses).toBe(SEALED_RECORD.remainingUses);
  expect(
    mpcMaterialActivationRefsEqual(
      runtime.sealedRecord.ed25519Restore.materialActivation,
      SEALED_RECORD.ed25519Restore.materialActivation,
    ),
  ).toBe(true);
});

test('rebinds a prepared Ed25519 state to a renewed active Wallet Session identity', () => {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const originalAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const renewedAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD, {
    authorizationSessionId: 'authorization:ed25519-rebound',
    walletSessionId: 'wallet-session:ed25519-rebound',
    quotaId: 'quota:ed25519-rebound',
  });
  const originalState = buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: originalAuthorization.walletSessionTokens.ed25519.walletSessionJwt,
    authority: originalAuthorization.authority,
    nowMs: runtime.expiresAtMs - 1,
  });

  const rebound = authorizeRouterAbEd25519WalletSessionState({
    state: originalState,
    authorization: renewedAuthorization,
    nowMs: runtime.expiresAtMs - 1,
  });

  expect(rebound).not.toBeNull();
  expect(rebound?.walletSessionId).toBe(renewedAuthorization.walletSessionId);
  expect(rebound?.quotaId).toBe(renewedAuthorization.quotaId);
  expect(rebound?.signingLane.identity.walletSessionId).toBe(renewedAuthorization.walletSessionId);
  expect(rebound?.signingLane.identity.quotaId).toBe(renewedAuthorization.quotaId);
  expect(rebound?.signingWalletSession.auth.walletSessionJwt).toBe(
    renewedAuthorization.walletSessionTokens.ed25519.walletSessionJwt,
  );
});

test('rebinds durable Ed25519 policy to a renewed threshold session', async () => {
  const durableRecord = buildPasskeyEd25519SealedSessionRecordFixture({
    thresholdSessionId: 'ed25519-durable-policy-session',
    remainingUses: 2,
    expiresAtMs: 1_900_000_000_000,
  });
  const renewedRecord = buildPasskeyEd25519SealedSessionRecordFixture({
    thresholdSessionId: 'ed25519-renewed-authorization-session',
    remainingUses: 9,
    expiresAtMs: 1_900_000_060_000,
  });
  const runtime = parseExactEd25519SealedSessionRuntime(durableRecord);
  if (!runtime) throw new Error('failed to parse durable Ed25519 runtime fixture');
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(renewedRecord);

  const rebound = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization,
    nowMs: durableRecord.expiresAtMs - 1,
  });

  expect(rebound.thresholdSessionId).toBe(renewedRecord.thresholdSessionIds.ed25519);
  expect(rebound.signingLane.identity.thresholdSessionId).toBe(
    renewedRecord.thresholdSessionIds.ed25519,
  );
  expect(rebound.remainingUses).toBe(durableRecord.remainingUses);
  expect(rebound.signingWalletSession.expiresAtMs).toBe(durableRecord.expiresAtMs);
  expect(rebound.authority).toEqual(authorization.authority);
});

test('promotes renewed Ed25519 authorization to a current durable seal without changing policy', async () => {
  const durableRecord = buildPasskeyEd25519SealedSessionRecordFixture({
    thresholdSessionId: 'ed25519-promotion-session-old',
    remainingUses: 4,
    expiresAtMs: 1_900_000_000_000,
  });
  const renewedRecord = buildPasskeyEd25519SealedSessionRecordFixture({
    thresholdSessionId: 'ed25519-promotion-session-current',
  });
  const runtime = parseExactEd25519SealedSessionRuntime(durableRecord);
  if (!runtime) throw new Error('failed to parse durable Ed25519 runtime fixture');
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(renewedRecord);
  const rebound = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization,
    nowMs: durableRecord.expiresAtMs - 1,
  });
  const restore = buildPasskeyEd25519RestoreMetadata({
    rpId: runtime.factor.kind === 'passkey' ? runtime.factor.rpId : '',
    nearAccountId: runtime.nearAccountId,
    nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
    relayerKeyId: runtime.relayerKeyId,
    participantIds: runtime.participantIds,
    runtimePolicyScope: runtime.runtimePolicyScope,
    signerSlot: runtime.signerSlot,
    routerAbNormalSigning: runtime.routerAbNormalSigning,
    credentialIdB64u: runtime.factor.kind === 'passkey' ? runtime.factor.credentialIdB64u : '',
    materialActivation: durableRecord.ed25519Restore.materialActivation,
  });
  const persistence = new SessionPersistenceFixture({
    ok: true,
    sealedSecretB64u: 'promoted-ed25519-sealed-secret',
    remainingUses: durableRecord.remainingUses,
    expiresAtMs: durableRecord.expiresAtMs,
  });

  await persistPasskeyEd25519YaoSessionForRefresh({
    persistence,
    session: rebound,
    prfFirstB64u: 'promoted-ed25519-prf-first',
    ed25519Restore: restore,
    materialActivation: restore.materialActivation,
  });

  expect(persistence.calls.map(sessionPersistenceCallKind)).toEqual(['hydrate', 'persist']);
  expect(persistence.calls[0].input).toMatchObject({
    thresholdSessionId: renewedRecord.thresholdSessionIds.ed25519,
    expiresAtMs: durableRecord.expiresAtMs,
    remainingUses: durableRecord.remainingUses,
    transport: {
      walletSessionJwt: authorization.walletSessionTokens.ed25519.walletSessionJwt,
      ed25519Restore: restore,
    },
  });
  expect(persistence.calls[1].input).toMatchObject({
    thresholdSessionId: renewedRecord.thresholdSessionIds.ed25519,
    transport: { ed25519Restore: restore },
  });
});

test('rejects an Ed25519 Wallet Session projection with a different lifecycle', () => {
  const fixture = buildPasskeyYaoWalletSession();
  expect(() =>
    buildPasskeyWalletSessionAuthorization({
      expiresAtMs: fixture.expiresAtMs + 1,
      walletSessionJwt: fixture.walletSessionJwt,
    }),
  ).toThrow('Wallet Session authorization projection is invalid');
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
      materialActivation: fixture.ed25519Restore.materialActivation,
    }),
  ).rejects.toThrow('Ed25519 Yao sealed refresh persistence failed (not_enabled)');
});

test('rejects refresh persistence when the material activation reference changes', async () => {
  const fixture = buildPasskeyYaoWalletSession();
  const persistence = new SessionPersistenceFixture({
    ok: true,
    sealedSecretB64u: 'sealed-session-refresh-secret',
    remainingUses: 3,
    expiresAtMs: fixture.expiresAtMs,
  });

  await expect(
    persistPasskeyEd25519YaoSessionForRefresh({
      persistence,
      session: fixture.session,
      prfFirstB64u: 'passkey-prf-first-ed25519-yao-sealed-refresh',
      ed25519Restore: fixture.ed25519Restore,
      materialActivation: buildMpcMaterialActivationRefFixture(
        'ed25519-sealed-refresh-replacement',
        WALLET_ID,
      ),
    }),
  ).rejects.toThrow('Ed25519 Yao sealed refresh metadata does not match the exact session');
  expect(persistence.calls).toEqual([]);
});

import { expect, test } from '@playwright/test';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
  type PasskeyEd25519YaoSessionPersistencePort,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  authorizeRouterAbEd25519WalletSessionState,
  buildPasskeyRouterAbEd25519WalletSessionState,
  rebindRouterAbEd25519WalletSessionStateFromExactRuntime,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';
import {
  buildActiveWalletSessionAuthorizationProjection,
  type ActiveWalletSessionAuthorizationProjection,
  walletSessionAuthorizationIdForCurve,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import {
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { RegistrationEstablishedSession } from '@shared/utils/registrationEstablishedSession';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';
import { parseNamedNearAccountId } from '@shared/utils/near';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type { CurrentEd25519SealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';

const SEALED_RECORD = buildPasskeyEd25519SealedSessionRecordFixture();
const WALLET_ID = toWalletId(SEALED_RECORD.walletId);
const THRESHOLD_SESSION_ID_RESULT = parseThresholdEd25519SessionId(
  SEALED_RECORD.thresholdSessionIds.ed25519,
);
if (!THRESHOLD_SESSION_ID_RESULT.ok) {
  throw new Error(THRESHOLD_SESSION_ID_RESULT.error.message);
}
const THRESHOLD_SESSION_ID = THRESHOLD_SESSION_ID_RESULT.value;
const NEAR_ACCOUNT_ID_RESULT = parseNamedNearAccountId(SEALED_RECORD.ed25519Restore.nearAccountId);
if (!NEAR_ACCOUNT_ID_RESULT.ok) {
  throw new Error(NEAR_ACCOUNT_ID_RESULT.message);
}
const NEAR_ACCOUNT_ID = NEAR_ACCOUNT_ID_RESULT.value;
const NEAR_SIGNING_KEY_ID = parseNearEd25519SigningKeyId(
  SEALED_RECORD.ed25519Restore.nearEd25519SigningKeyId,
);
function requirePasskeyCredentialId(record: CurrentEd25519SealedSessionRecord): string {
  const credentialIdB64u = record.ed25519Restore.credentialIdB64u;
  if (typeof credentialIdB64u !== 'string' || credentialIdB64u.length === 0) {
    throw new Error('Passkey sealed-session fixture is missing its credential id');
  }
  return credentialIdB64u;
}

const CREDENTIAL_ID_B64U = requirePasskeyCredentialId(SEALED_RECORD);
const RUNTIME_POLICY_SCOPE = normalizeRuntimePolicyScope(
  SEALED_RECORD.ed25519Restore.runtimePolicyScope,
);

type SessionPersistenceCall = { kind: 'hydrate'; input: unknown };

function ed25519AuthorizationToken(authorization: ActiveWalletSessionAuthorizationProjection) {
  if (authorization.walletSessionTokens.kind === 'evm_family_ecdsa') {
    throw new Error('Ed25519 authorization fixture has no Ed25519 token');
  }
  return authorization.walletSessionTokens.ed25519;
}

function requireNamedNearAccountId(value: string) {
  const parsed = parseNamedNearAccountId(value);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

class SessionPersistenceFixture implements PasskeyEd25519YaoSessionPersistencePort {
  readonly calls: SessionPersistenceCall[] = [];

  constructor(private readonly hydrateResult: WarmSessionSealAndPersistResult) {}

  async hydrateSigningSession(
    input: Parameters<PasskeyEd25519YaoSessionPersistencePort['hydrateSigningSession']>[0],
  ): Promise<void> {
    this.calls.push({ kind: 'hydrate', input });
    if (!this.hydrateResult.ok) {
      throw new Error(
        `Warm-session cache could not persist sealed refresh material (${this.hydrateResult.code}): ${this.hydrateResult.message}`,
      );
    }
  }
}

function sessionPersistenceCallKind(call: SessionPersistenceCall): SessionPersistenceCall['kind'] {
  return call.kind;
}

function buildPasskeyWalletSessionAuthorization(args: {
  expiresAtMs: number;
  walletSessionToken: string;
  authority?: WalletAuthAuthorityRef;
}) {
  const expected = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const authorizationId = walletSessionAuthorizationIdForCurve(expected, 'ed25519');
  if (!authorizationId) throw new Error('missing Ed25519 authorization id in fixture');
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: expected.walletId,
    walletSessionId: expected.walletSessionId,
    quotaId: expected.quotaId,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId,
        walletSessionToken: args.walletSessionToken,
        thresholdSessionId: THRESHOLD_SESSION_ID,
      },
    },
    authMethod: 'passkey',
    authority: args.authority ?? expected.authority,
    expiresAtMs: args.expiresAtMs,
  });
}

async function buildPasskeyYaoWalletSession() {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const authorizationFixture = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const authorizationToken = ed25519AuthorizationToken(authorizationFixture);
  const session = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization: authorizationFixture,
    nowMs: runtime.expiresAtMs - 1,
  });
  return {
    ed25519Restore: buildPasskeyEd25519RestoreMetadata({
      rpId: SEALED_RECORD.ed25519Restore.rpId,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      relayerKeyId: SEALED_RECORD.ed25519Restore.relayerKeyId,
      participantIds: SEALED_RECORD.ed25519Restore.participantIds,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signerSlot: SEALED_RECORD.ed25519Restore.signerSlot,
      routerAbNormalSigning: SEALED_RECORD.ed25519Restore.routerAbNormalSigning,
      credentialIdB64u: CREDENTIAL_ID_B64U,
      materialActivation: SEALED_RECORD.ed25519Restore.materialActivation,
    }),
    expiresAtMs: runtime.expiresAtMs,
    walletSessionToken: authorizationToken.walletSessionToken,
    session,
  };
}

function buildRegistrationEstablishedPasskeySession(): RegistrationEstablishedSession {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const authorizationToken = ed25519AuthorizationToken(authorization);
  const authorizationId = walletSessionAuthorizationIdForCurve(authorization, 'ed25519');
  if (!authorizationId) throw new Error('registration fixture is missing Ed25519 authorization id');
  return {
    kind: 'registration_established_wallet_session_v1',
    walletId: WALLET_ID,
    authorizationId,
    walletSessionId: authorization.walletSessionId,
    quotaId: authorization.quotaId,
    expiresAtMs: runtime.expiresAtMs,
    remainingUses: runtime.remainingUses,
    tokens: {
      kind: 'near_ed25519',
      ed25519: {
        sessionKind: 'opaque',
        walletSessionToken: authorizationToken.walletSessionToken,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
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
    authorizationId: registrationEstablishedSession.authorizationId,
    quotaId: registrationEstablishedSession.quotaId,
    thresholdSessionId: token.thresholdSessionId,
    remainingUses: registrationEstablishedSession.remainingUses,
    expiresAtMs: registrationEstablishedSession.expiresAtMs,
    runtimePolicyScope: token.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion || '',
    routerAbNormalSigning: token.routerAbNormalSigning,
    walletSessionToken: token.walletSessionToken,
    nowMs: registrationEstablishedSession.expiresAtMs - 1,
  });
  if (!signingWalletSession.ok) {
    throw new Error(`registration fixture session is invalid: ${signingWalletSession.reason}`);
  }
  return buildPasskeyRouterAbEd25519WalletSessionState({
    walletId: WALLET_ID,
    nearAccountId: requireNamedNearAccountId(token.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(token.nearEd25519SigningKeyId),
    signerSlot: SEALED_RECORD.ed25519Restore.signerSlot,
    rpId: toRpId(SEALED_RECORD.ed25519Restore.rpId),
    credentialIdB64u: CREDENTIAL_ID_B64U,
    relayerUrl: SEALED_RECORD.relayerUrl,
    authority: buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD).authority,
    signingWalletSession: signingWalletSession.value,
  });
}

test('persists and verifies a passkey Yao session seal for page refresh', async () => {
  const fixture = await buildPasskeyYaoWalletSession();
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

  expect(persistence.calls.map(sessionPersistenceCallKind)).toEqual(['hydrate']);
  expect(persistence.calls[0].input).toMatchObject({
    thresholdSessionId: THRESHOLD_SESSION_ID,
    remainingUses: 3,
    transport: {
      curve: 'ed25519',
      authMethod: 'passkey',
      walletId: WALLET_ID,
      walletSessionToken: fixture.walletSessionToken,
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
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    relayerKeyId: SEALED_RECORD.ed25519Restore.relayerKeyId,
    participantIds: SEALED_RECORD.ed25519Restore.participantIds,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    signerSlot: SEALED_RECORD.ed25519Restore.signerSlot,
    routerAbNormalSigning: SEALED_RECORD.ed25519Restore.routerAbNormalSigning,
    credentialIdB64u: CREDENTIAL_ID_B64U,
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

  expect(persistence.calls.map(sessionPersistenceCallKind)).toEqual(['hydrate']);
});

test('authorizes Ed25519 normal signing from the correlated Wallet Session projection', async () => {
  const fixture = await buildPasskeyYaoWalletSession();
  const authorization = buildPasskeyWalletSessionAuthorization({
    expiresAtMs: fixture.expiresAtMs,
    walletSessionToken: fixture.walletSessionToken,
  });

  const authorized = authorizeRouterAbEd25519WalletSessionState({
    state: fixture.session,
    authorization,
    nowMs: fixture.expiresAtMs - 1,
  });

  expect(authorized?.walletSessionId).toBe(authorization.walletSessionId);
  expect(authorized?.walletSessionAuthorization).toBe(authorization);
});

test('rejects a renewed Ed25519 projection with a hostile authority digest', async () => {
  const fixture = await buildPasskeyYaoWalletSession();
  const hostileAuthorization = buildPasskeyWalletSessionAuthorization({
    expiresAtMs: fixture.expiresAtMs,
    walletSessionToken: fixture.walletSessionToken,
    authority: buildWalletAuthAuthorityRefFixture({
      walletId: WALLET_ID,
      label: 'hostile-ed25519-authority',
    }),
  });

  const authorized = authorizeRouterAbEd25519WalletSessionState({
    state: fixture.session,
    authorization: hostileAuthorization,
    nowMs: fixture.expiresAtMs - 1,
  });

  expect(authorized).toBeNull();
});

test('accepts a renewed authorization expiry while retaining the sealed runtime expiry', async () => {
  const fixture = await buildPasskeyYaoWalletSession();
  const renewedExpiresAtMs = fixture.expiresAtMs + 60_000;
  const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD, {
    authorizationExpiresAtMs: renewedExpiresAtMs,
  });
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const renewedState = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization,
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

test('renews Wallet Session authorization without changing Ed25519 material activation', async () => {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const originalAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const renewedAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD, {
    authorizationId: 'wallet-session-authorization:ed25519-renewed',
    walletSessionId: 'wallet-session:ed25519-renewed',
    quotaId: 'quota:ed25519-renewed',
  });
  const originalState = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization: originalAuthorization,
    nowMs: runtime.expiresAtMs - 1,
  });
  const renewedState = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization: renewedAuthorization,
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
  expect(walletSessionAuthorizationIdForCurve(renewedAuthorization, 'ed25519')).not.toBe(
    walletSessionAuthorizationIdForCurve(originalAuthorization, 'ed25519'),
  );
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

test('rebinds a prepared Ed25519 state to a renewed active Wallet Session identity', async () => {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const originalAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD);
  const renewedAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(SEALED_RECORD, {
    walletSessionId: 'wallet-session:ed25519-rebound',
    quotaId: 'quota:ed25519-rebound',
  });
  const originalState = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization: originalAuthorization,
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
  const renewedAuthorizationToken = ed25519AuthorizationToken(renewedAuthorization);
  expect(rebound?.signingWalletSession.auth.walletSessionToken).toBe(
    renewedAuthorizationToken.walletSessionToken,
  );
});

test('keeps durable Ed25519 material identity when authorization is renewed', async () => {
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

  expect(rebound.thresholdSessionId).toBe(durableRecord.thresholdSessionIds.ed25519);
  expect(rebound.signingLane.identity.thresholdSessionId).toBe(
    durableRecord.thresholdSessionIds.ed25519,
  );
  expect(rebound.remainingUses).toBe(durableRecord.remainingUses);
  expect(rebound.signingWalletSession.expiresAtMs).toBe(durableRecord.expiresAtMs);
  expect(rebound.authority).toEqual(authorization.authority);
});

test('persists the exact durable Ed25519 material identity after authorization renewal', async () => {
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

  expect(persistence.calls.map(sessionPersistenceCallKind)).toEqual(['hydrate']);
  expect(persistence.calls[0].input).toMatchObject({
    thresholdSessionId: durableRecord.thresholdSessionIds.ed25519,
    expiresAtMs: durableRecord.expiresAtMs,
    remainingUses: durableRecord.remainingUses,
    transport: {
      walletSessionToken: ed25519AuthorizationToken(authorization).walletSessionToken,
      ed25519Restore: restore,
    },
  });
});

test('fails the lifecycle when the durable Yao session seal is unavailable', async () => {
  const fixture = await buildPasskeyYaoWalletSession();
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
  ).rejects.toThrow(
    'Warm-session cache could not persist sealed refresh material (not_enabled): sealed refresh is disabled',
  );
});

test('rejects refresh persistence when the material activation reference changes', async () => {
  const fixture = await buildPasskeyYaoWalletSession();
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

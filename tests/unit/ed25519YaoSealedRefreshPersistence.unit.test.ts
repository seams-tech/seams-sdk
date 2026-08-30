import { expect, test } from '@playwright/test';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
  type PasskeyEd25519YaoSessionPersistencePort,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import { rebindRouterAbEd25519WalletSessionStateFromExactRuntime } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';
import {
  buildPasskeyExactEd25519AuthorizationFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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

function ed25519AuthorizationToken(
  authorization: ReturnType<typeof buildPasskeyExactEd25519AuthorizationFixture>,
) {
  return authorization.operationCredential;
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

async function buildPasskeyYaoWalletSession() {
  const runtime = parseExactEd25519SealedSessionRuntime(SEALED_RECORD);
  if (!runtime) throw new Error('failed to parse exact passkey Yao runtime fixture');
  const authorizationFixture = buildPasskeyExactEd25519AuthorizationFixture(SEALED_RECORD);
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
    walletSessionToken: authorizationToken.token,
    session,
  };
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
  const authorization = buildPasskeyExactEd25519AuthorizationFixture(renewedRecord);

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
  expect(rebound.authority).toMatchObject({
    walletId: authorization.session.walletId,
    walletAuthMethodId: authorization.selectedAuthMethod.walletAuthMethodId,
    authorityDigest: authorization.selectedAuthority.authorityDigestB64u,
  });
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
  const authorization = buildPasskeyExactEd25519AuthorizationFixture(renewedRecord);
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
    remainingUses: Math.min(durableRecord.remainingUses, authorization.status.remainingUses),
    transport: {
      walletSessionToken: ed25519AuthorizationToken(authorization).token,
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

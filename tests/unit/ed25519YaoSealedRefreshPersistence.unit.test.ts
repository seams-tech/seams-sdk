import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  persistPasskeyEd25519YaoSessionForRefresh,
  type PasskeyEd25519YaoSessionPersistencePort,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { resolveRouterAbEd25519WalletSessionStateFromRecord } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { runtimeEd25519RouterAbNormalSigningState } from './helpers/availableSigningLanes.fixtures';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';

const WALLET_ID = 'wallet-ed25519-yao-sealed-refresh';
const NEAR_ACCOUNT_ID = toAccountId('ed25519-yao-sealed-refresh.testnet');
const NEAR_SIGNING_KEY_ID = 'near-ed25519-key-sealed-refresh';
const THRESHOLD_SESSION_ID = 'threshold-session-ed25519-yao-sealed-refresh';
const SIGNING_GRANT_ID = 'signing-grant-ed25519-yao-sealed-refresh';

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

function buildWalletSessionJwt(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingGrantId: SIGNING_GRANT_ID,
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture-signature`;
}

function buildPasskeyYaoWalletSession() {
  const expiresAtMs = Date.now() + 60_000;
  const record = persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    rpId: 'wallet.example.localhost',
    relayerUrl: 'https://relay.example.test',
    relayerKeyId: 'ed25519-signing-worker-sealed-refresh',
    runtimePolicyScope: {
      orgId: 'org-sealed-refresh',
      projectId: 'project-sealed-refresh',
      envId: 'env-sealed-refresh',
      signingRootVersion: 'root-v1',
    },
    participantIds: [1, 2],
    signerSlot: 1,
    routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
    sessionId: THRESHOLD_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
    expiresAtMs,
    remainingUses: 3,
    jwt: buildWalletSessionJwt(),
    passkeyCredentialIdB64u: 'credential-ed25519-yao-sealed-refresh',
    source: 'registration',
  });
  const session = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
  if (!session) throw new Error('failed to build passkey Yao Wallet Session fixture');
  return { expiresAtMs, session };
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
      walletSessionJwt: buildWalletSessionJwt(),
    },
  });
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
    }),
  ).rejects.toThrow('Ed25519 Yao sealed refresh persistence failed (not_enabled)');
});

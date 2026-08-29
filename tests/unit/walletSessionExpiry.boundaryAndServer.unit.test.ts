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
import {
  readClientWalletSessionAuthorization,
  type ClientWalletSessionAuthorizationPersistenceDeps,
} from '@/core/signingEngine/session/persistence/clientSessionPersistence';
import {
  buildActiveWalletSessionAuthorizationProjection,
  parseWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationExactActiveReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseThresholdEd25519SessionId,
  parseWebAuthnCredentialIdB64u,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { buildWalletAuthAuthorityRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildEd25519PasskeySigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import type { SessionParseFailureReason } from '@server/core/sessionValidation';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';

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

type SelectedWalletAuthorityResult = Awaited<
  ReturnType<ClientWalletSessionAuthorizationPersistenceDeps['resolveSelectedWalletAuthority']>
>;

class ClientWalletSessionAuthorizationPersistenceHarness {
  readonly deps: ClientWalletSessionAuthorizationPersistenceDeps;
  readResult: WalletSessionAuthorizationExactActiveReadResult;
  readInput:
    | Parameters<ClientWalletSessionAuthorizationPersistenceDeps['readExactActiveForWallet']>[0]
    | null = null;

  constructor(
    readonly selected: SelectedWalletAuthorityResult,
    readResult: WalletSessionAuthorizationExactActiveReadResult,
  ) {
    this.readResult = readResult;
    this.deps = {
      resolveSelectedWalletAuthority: this.resolveSelectedWalletAuthority.bind(this),
      readExactActiveForWallet: this.readExactActiveForWallet.bind(this),
    };
  }

  async resolveSelectedWalletAuthority(): Promise<SelectedWalletAuthorityResult> {
    return this.selected;
  }

  async readExactActiveForWallet(
    input: Parameters<
      ClientWalletSessionAuthorizationPersistenceDeps['readExactActiveForWallet']
    >[0],
  ): Promise<WalletSessionAuthorizationExactActiveReadResult> {
    this.readInput = input;
    return this.readResult;
  }
}

function linkedRuntimeEd25519Lane(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceUnlockRuntimeFixture>>,
  credentialIdB64u: WebAuthnCredentialIdB64u = fixture.authMethod.credentialIdB64u,
) {
  return buildEd25519PasskeySigningLane({
    walletId: fixture.walletId,
    nearAccountId: toAccountId(fixture.ed25519Session.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      fixture.ed25519Session.nearEd25519SigningKeyId,
    ),
    signerSlot: 1,
    auth: {
      kind: 'passkey',
      rpId: toRpId(String(fixture.authMethod.rpId)),
      credentialIdB64u,
    },
    walletSessionId: fixture.operationCredential.walletSessionId,
    quotaId: fixture.ed25519Session.quotaId,
    thresholdSessionId: fixture.ed25519Session.thresholdSessionId,
    storageSource: 'login',
  });
}

function webAuthnCredentialId(value: string): WebAuthnCredentialIdB64u {
  const parsed = parseWebAuthnCredentialIdB64u(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function validTokenVerifier(): { valid: true; payload: { sub: string; exp: number } } {
  return { valid: true, payload: { sub: 'wallet', exp: NOW_SECONDS + 1 } };
}

function walletSessionTokenFixture(): string {
  return 'opaque-wallet-session-token:refactor-92-boundary';
}

function activeAuthorizationFixture(expiresAtMs: number, authMethod: 'passkey' | 'email_otp') {
  const walletId = LANE.identity.signer.account.wallet.walletId;
  const walletSessionId = parseWalletSessionId('refactor-92-wallet-session');
  const authorizationId = parseWalletSessionAuthorizationId('refactor-92-authorization');
  const quotaId = parseMpcWalletSigningQuotaId('refactor-92-quota');
  const thresholdSessionId = parseThresholdEd25519SessionId('refactor-92-session');
  if (!authorizationId.ok || !walletSessionId.ok || !quotaId.ok || !thresholdSessionId.ok) {
    throw new Error('Failed to build Refactor 92 authorization fixture');
  }
  return buildActiveWalletSessionAuthorizationProjection({
    walletId,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId: authorizationId.value,
        walletSessionToken: walletSessionTokenFixture(),
        thresholdSessionId: thresholdSessionId.value,
      },
    },
    authMethod,
    authority: buildWalletAuthAuthorityRefFixture({
      walletId: String(walletId),
      label: 'refactor-92-boundary',
    }),
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

test('Ed25519 export preflight reads only the selected exact Wallet Session', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const lane = linkedRuntimeEd25519Lane(fixture);
  const harness = new ClientWalletSessionAuthorizationPersistenceHarness(
    {
      kind: 'resolved',
      selection: fixture.selection,
      authMethod: fixture.authMethod,
      authority: fixture.authority,
      signerMaterials: fixture.signerMaterials,
      exportRoot: null,
    },
    {
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    },
  );
  const nowMs = Date.now();
  await expect(
    readClientWalletSessionAuthorization(harness.deps, {
      kind: 'ed25519',
      laneIdentity: lane.identity,
      nowMs,
    }),
  ).resolves.toEqual(
    expect.objectContaining({
      kind: 'active',
      expiresAtMs: fixture.activeWalletSession.expiresAtMs,
    }),
  );
  expect(harness.readInput).toEqual({
    walletId: fixture.walletId,
    authorityId: fixture.authority.authorityId,
    authMethodId: fixture.authMethod.walletAuthMethodId,
  });

  const siblingLane = linkedRuntimeEd25519Lane(fixture, webAuthnCredentialId('sibling-credential'));
  await expect(
    readClientWalletSessionAuthorization(harness.deps, {
      kind: 'ed25519',
      laneIdentity: siblingLane.identity,
      nowMs,
    }),
  ).resolves.toEqual(expect.objectContaining({ kind: 'invalid', reason: 'scope_mismatch' }));

  const failures = [
    { read: { kind: 'missing' as const }, expected: { kind: 'missing' } },
    {
      read: { kind: 'corrupt' as const },
      expected: { kind: 'invalid', reason: 'malformed' },
    },
    {
      read: { kind: 'persistence_unavailable' as const },
      expected: { kind: 'unavailable', reason: 'persistence_unavailable' },
    },
  ];
  for (const failure of failures) {
    harness.readResult = failure.read;
    await expect(
      readClientWalletSessionAuthorization(harness.deps, {
        kind: 'ed25519',
        laneIdentity: lane.identity,
        nowMs,
      }),
    ).resolves.toEqual(expect.objectContaining(failure.expected));
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

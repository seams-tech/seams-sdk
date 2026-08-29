import { expect, test } from '@playwright/test';
import type { ExactWalletSessionStatusV2 } from '@server/authorization/domain';
import {
  applySeededStatusTransition,
  seedExactWalletSessionStatusFixture,
  SEEDED_TRANSITION_AT_MS,
  UNKNOWN_PRIMARY_CREDENTIAL_TOKEN,
  type ExactWalletSessionStatusPersistenceFixture,
  type SeededStatusTransition,
} from './helpers/exactWalletSessionStatusPersistence.fixtures';

/**
 * `/wallet/session/status` reads its whole lifecycle from persistence: expiry,
 * exhaustion, retirement, and an unavailable authority, method, or capability
 * are typed results rather than exceptions, and every observed branch carries
 * the complete digest-free authorization with its quota projection.
 */
async function readStatus(
  fixture: ExactWalletSessionStatusPersistenceFixture,
  nowMs: number,
): Promise<ExactWalletSessionStatusV2> {
  return await fixture.service.readExactWalletSessionStatusByOperationCredential({
    tenantId: fixture.tenantId,
    token: fixture.operationCredential.token,
    nowMs,
  });
}

async function withFixture(
  label: string,
  body: (fixture: ExactWalletSessionStatusPersistenceFixture) => Promise<void>,
): Promise<void> {
  const fixture = await seedExactWalletSessionStatusFixture({ label });
  try {
    await body(fixture);
  } finally {
    fixture.cleanup();
  }
}

test('exact status returns the complete digest-free authorization and active quota', async () => {
  await withFixture('lifecycle-active', async (fixture) => {
    const status = await readStatus(fixture, fixture.issuedAtMs + 1);
    if (status.kind !== 'active') throw new Error(`expected active, observed ${status.kind}`);

    expect(status.session).toEqual({
      kind: 'wallet_session_authorization_v2',
      tenantId: fixture.tenantId,
      principalId: fixture.principalId,
      walletId: fixture.walletId,
      authorityId: fixture.authority.authorityId,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      authorityDigestB64u: fixture.authority.authorityDigestB64u,
      authorityRevocationEpoch: fixture.authority.revocationEpoch,
      mintId: status.session.mintId,
      authorizationId: status.session.authorizationId,
      walletSessionId: fixture.walletSessionId,
      quotaId: fixture.quotaId,
      capabilitySubjects: status.session.capabilitySubjects,
      createdAtMs: fixture.issuedAtMs,
      expiresAtMs: fixture.expiresAtMs,
    });
    expect(status.session.capabilitySubjects.length).toBeGreaterThan(0);
    expect(JSON.stringify(status)).not.toContain('operationCredential');
    expect(status.quota).toEqual({
      kind: 'exact_wallet_session_quota_projection_v1',
      lifecycle: 'active',
      tenantId: fixture.tenantId,
      principalId: fixture.principalId,
      walletSessionId: fixture.walletSessionId,
      quotaId: fixture.quotaId,
      remainingUses: 3,
      expiresAtMs: fixture.expiresAtMs,
    });
  });
});

test('exact status returns missing for an unknown or wrong-family credential', async () => {
  await withFixture('lifecycle-missing', async (fixture) => {
    for (const token of [
      UNKNOWN_PRIMARY_CREDENTIAL_TOKEN,
      fixture.operationCredential.token.replace(/^wst_/, 'wsh_'),
    ]) {
      await expect(
        fixture.service.readExactWalletSessionStatusByOperationCredential({
          tenantId: fixture.tenantId,
          token,
          nowMs: fixture.issuedAtMs + 1,
        }),
      ).resolves.toEqual({ kind: 'missing' });
    }
  });
});

test('exact status returns expired instead of throwing once the authorization lapses', async () => {
  await withFixture('lifecycle-expired', async (fixture) => {
    const status = await readStatus(fixture, fixture.expiresAtMs);
    if (status.kind !== 'expired') throw new Error(`expected expired, observed ${status.kind}`);
    expect(status.session.walletSessionId).toBe(fixture.walletSessionId);
    expect(status.quota.expiresAtMs).toBe(fixture.expiresAtMs);
  });
});

const UNAVAILABLE_CASES: readonly {
  readonly label: string;
  readonly transition: SeededStatusTransition;
  readonly kind: ExactWalletSessionStatusV2['kind'];
}[] = [
  { label: 'exhausted', transition: 'exhaust_quota', kind: 'exhausted' },
  { label: 'retired', transition: 'retire_authorization', kind: 'retired' },
  { label: 'authority', transition: 'revoke_authority', kind: 'authority_unavailable' },
  { label: 'method', transition: 'revoke_auth_method', kind: 'method_unavailable' },
  {
    label: 'capability',
    transition: 'retarget_session_material',
    kind: 'capability_unavailable',
  },
];

for (const testCase of UNAVAILABLE_CASES) {
  test(`exact status returns ${testCase.kind} and keeps the authorization readable`, async () => {
    await withFixture(`lifecycle-${testCase.label}`, async (fixture) => {
      await applySeededStatusTransition(fixture, testCase.transition);

      const status = await readStatus(fixture, SEEDED_TRANSITION_AT_MS + 1);
      if (status.kind !== testCase.kind) {
        throw new Error(`expected ${testCase.kind}, observed ${status.kind}`);
      }
      if (status.kind === 'missing') throw new Error('unreachable: missing carries no session');
      // A typed unavailable result still publishes the exact identity a browser
      // needs to reconcile and retire its own record.
      expect(status.session.walletSessionId).toBe(fixture.walletSessionId);
      expect(status.session.authorityId).toBe(fixture.authority.authorityId);
      expect(status.quota.quotaId).toBe(fixture.quotaId);
      expect(status.quota.expiresAtMs).toBe(fixture.expiresAtMs);
    });
  });
}

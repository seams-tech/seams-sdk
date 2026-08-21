import { expect, test } from '@playwright/test';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { parseSessionOrigin } from '../../packages/wallet-server/src/authorization/domain';
import { parseReusableWalletSessionMintId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseWalletAuthMethodId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildPasskeyWalletSessionIssuanceFixture,
  type PasskeyWalletSessionIssuanceFixture,
} from './helpers/authorizationCore.fixtures';
import { insertWalletAuthMethod } from './helpers/cloudflareD1RouterApiAuthService.fixtures';

/**
 * Wallet Sessions record which auth method issued them, so pausing or revoking
 * one credential can select every session it issued.
 *
 * This lives apart from the wider D1 authorization suite because that file
 * imports fixtures retired by the opaque-session cutover and cannot currently
 * load — and provenance is exactly the invariant that must stay verifiable.
 */
const signerMigrations = listD1MigrationFiles('d1-signer');

function createService(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  namespace: string,
): AuthorizationService {
  const store = new CloudflareD1AuthorizationStore({
    database,
    namespace,
    walletSignerScope: {
      namespace,
      orgId: 'test-org',
      projectId: 'test-project',
      envId: 'test-env',
    },
  });
  return new AuthorizationService({
    policy: capabilityPolicyPort,
    sessions: store,
    evidence: store,
    grants: store,
    authorizedOperations: store,
    audit: store,
  });
}

function requiredMintId(value: string) {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredWalletAuthMethodId(value: string) {
  const parsed = parseWalletAuthMethodId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function passkeyAuthMethodRecord(
  fixture: PasskeyWalletSessionIssuanceFixture,
  status: 'active' | 'revoked',
  updatedAtMs: number,
) {
  return {
    version: 'wallet_auth_method_v1' as const,
    kind: 'passkey' as const,
    status,
    walletId: String(fixture.authority.walletId),
    rpId: String(fixture.authority.verifier.rpId),
    credentialIdB64u: String(fixture.authority.factor.credentialIdB64u),
    credentialPublicKeyB64u: 'credential-public-key',
    counter: 0,
    createdAtMs: fixture.session.createdAtMs,
    updatedAtMs,
  };
}

async function seedActivePasskeyAuthMethod(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  namespace: string,
  fixture: PasskeyWalletSessionIssuanceFixture,
): Promise<void> {
  await insertWalletAuthMethod({
    database,
    namespace,
    orgId: 'test-org',
    projectId: 'test-project',
    envId: 'test-env',
    record: passkeyAuthMethodRecord(fixture, 'active', fixture.session.createdAtMs),
  });
}

async function revokePasskeyAuthMethod(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  namespace: string,
  fixture: PasskeyWalletSessionIssuanceFixture,
  updatedAtMs: number,
): Promise<void> {
  const record = passkeyAuthMethodRecord(fixture, 'revoked', updatedAtMs);
  await database
    .prepare(
      `UPDATE wallet_auth_methods
          SET status = ?, record_json = ?, updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_auth_method_id = ?`,
    )
    .bind(
      record.status,
      JSON.stringify(record),
      record.updatedAtMs,
      namespace,
      'test-org',
      'test-project',
      'test-env',
      fixture.authorityRef.walletAuthMethodId,
    )
    .run();
}

test('stores the issuing auth method and refuses a read under a different one', async () => {
  // Every part of this was broken at once by a bad bind list: the value was
  // appended to a statement with no placeholder for it, the insert reserved a
  // column it never bound, and no reader selected the column back. Row counts
  // and replay equality all still passed. Only asserting the exact stored
  // value, and refusing a mismatched read, catches that shape of mistake.
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-provenance';
    const service = createService(temporary.database, namespace);
    const fixture = await buildPasskeyWalletSessionIssuanceFixture({
      tenantId: 'tenant-wallet-session-provenance',
      principalId: 'principal-wallet-session-provenance',
      walletId: 'wallet-session-provenance-wallet',
      credentialIdB64u: 'credential-wallet-session-provenance',
      rpId: 'example.test',
      origin: 'https://app.example.test',
      expiresAtMs: 1_900_000_100_000,
    });
    await seedActivePasskeyAuthMethod(temporary.database, namespace, fixture);
    const mintId = requiredMintId('unlock:wallet-session-provenance');
    const issuance = {
      tenantId: fixture.session.tenantId,
      principalId: fixture.session.principalId,
      walletId: fixture.authority.walletId,
      authority: fixture.authorityRef,
      mintId,
      remainingUses: 3,
      issuedAtMs: fixture.session.createdAtMs + 1,
      expiresAtMs: fixture.session.expiresAtMs,
    };
    await service.issueReusableWalletSession(issuance);

    const stored = await temporary.database
      .prepare(
        `SELECT wallet_auth_method_id, quota_id, expires_at_ms
             FROM reusable_wallet_sessions
            WHERE namespace = ? AND tenant_id = ? AND mint_id = ?`,
      )
      .bind(namespace, fixture.session.tenantId, String(mintId))
      .all<{
        readonly wallet_auth_method_id: string | null;
        readonly quota_id: string | null;
        readonly expires_at_ms: number | null;
      }>();
    const row = stored.results?.[0];
    expect(row?.wallet_auth_method_id).toBe(String(fixture.authorityRef.walletAuthMethodId));
    // A shifted bind list writes plausible-looking values into the wrong
    // columns, so the neighbours are checked too.
    expect(row?.quota_id).toBe(
      String(
        (
          await service.readWalletSessionAuthorizationByMint({
            ...issuance,
            nowMs: fixture.session.createdAtMs + 2,
          })
        )?.quota.quotaId,
      ),
    );
    expect(row?.expires_at_ms).toBe(fixture.session.expiresAtMs);

    const otherAuthority = {
      ...fixture.authorityRef,
      walletAuthMethodId: requiredWalletAuthMethodId('passkey:example.test:another-credential'),
    };
    await expect(
      service.readWalletSessionAuthorizationByMint({
        ...issuance,
        authority: otherAuthority,
        nowMs: fixture.session.createdAtMs + 2,
      }),
    ).rejects.toThrow(/identity does not match/);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('refuses Wallet Session readback and replay under a different stored auth method', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-auth-method-mismatch';
    const service = createService(temporary.database, namespace);
    const fixture = await buildPasskeyWalletSessionIssuanceFixture({
      tenantId: 'tenant-wallet-session-auth-method-mismatch',
      principalId: 'principal-wallet-session-auth-method-mismatch',
      walletId: 'wallet-session-auth-method-mismatch-wallet',
      credentialIdB64u: 'credential-wallet-session-original',
      rpId: 'example.test',
      origin: 'https://app.example.test',
      expiresAtMs: 1_900_000_100_000,
    });
    await seedActivePasskeyAuthMethod(temporary.database, namespace, fixture);
    const otherAuthority = await buildPasskeyWalletSessionIssuanceFixture({
      tenantId: fixture.session.tenantId,
      principalId: fixture.session.principalId,
      walletId: fixture.authority.walletId,
      credentialIdB64u: 'credential-wallet-session-other',
      rpId: 'example.test',
      origin: 'https://app.example.test',
      expiresAtMs: fixture.session.expiresAtMs,
    });
    const mintId = requiredMintId('unlock:wallet-session-auth-method-mismatch');
    await service.issueReusableWalletSession({
      tenantId: fixture.session.tenantId,
      principalId: fixture.session.principalId,
      walletId: fixture.authority.walletId,
      authority: fixture.authorityRef,
      mintId,
      remainingUses: 3,
      issuedAtMs: fixture.session.createdAtMs + 1,
      expiresAtMs: fixture.session.expiresAtMs,
    });
    await temporary.database
      .prepare(
        `UPDATE reusable_wallet_sessions
              SET wallet_auth_method_id = ?
            WHERE namespace = ? AND tenant_id = ? AND mint_id = ?`,
      )
      .bind(
        otherAuthority.authorityRef.walletAuthMethodId,
        namespace,
        fixture.session.tenantId,
        mintId,
      )
      .run();

    await expect(
      service.readWalletSessionAuthorizationByMint({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        nowMs: fixture.session.createdAtMs + 2,
      }),
    ).rejects.toThrow('identity does not match');
    await expect(
      service.issueReusableWalletSession({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId: fixture.authority.walletId,
        authority: fixture.authorityRef,
        mintId,
        remainingUses: 3,
        issuedAtMs: fixture.session.createdAtMs + 2,
        expiresAtMs: fixture.session.expiresAtMs,
      }),
    ).rejects.toThrow('issuance replay does not match');
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('revokes every reusable Wallet Session issued by one auth method', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-auth-method-revocation';
    const service = createService(temporary.database, namespace);
    const fixture = await buildPasskeyWalletSessionIssuanceFixture({
      tenantId: 'tenant-wallet-session-auth-method-revocation',
      principalId: 'principal-wallet-session-auth-method-revocation',
      walletId: 'wallet-session-auth-method-revocation-wallet',
      credentialIdB64u: 'credential-wallet-session-revoked',
      rpId: 'example.test',
      origin: 'https://app.example.test',
      expiresAtMs: 1_900_000_100_000,
    });
    await seedActivePasskeyAuthMethod(temporary.database, namespace, fixture);
    const mintId = requiredMintId('unlock:wallet-session-auth-method-revocation');
    const issuance = {
      tenantId: fixture.session.tenantId,
      principalId: fixture.session.principalId,
      walletId: fixture.authority.walletId,
      authority: fixture.authorityRef,
      mintId,
      remainingUses: 3,
      issuedAtMs: fixture.session.createdAtMs + 1,
      expiresAtMs: fixture.session.expiresAtMs,
    };
    const issued = await service.issueReusableWalletSession(issuance);
    const walletOrigin = parseSessionOrigin('https://wallet.example.test');
    const delayedExchange = await service.mintHostedWalletSeamsSessionExchange({
      tenantId: fixture.session.tenantId,
      walletSessionId: issued.session.walletSessionId,
      appOrigin: fixture.session.origin,
      walletOrigin,
      curve: 'ed25519',
      binding: { walletId: fixture.authority.walletId },
      issuedAtMs: fixture.session.createdAtMs + 2,
      expiresAtMs: fixture.session.expiresAtMs,
    });

    await revokePasskeyAuthMethod(
      temporary.database,
      namespace,
      fixture,
      fixture.session.createdAtMs + 2,
    );
    await service.revokeReusableWalletSessionsForAuthMethod({
      tenantId: fixture.session.tenantId,
      walletId: fixture.authority.walletId,
      walletAuthMethodId: fixture.authorityRef.walletAuthMethodId,
      nowMs: fixture.session.createdAtMs + 3,
    });
    await expect(
      service.issueReusableWalletSession({
        ...issuance,
        mintId: requiredMintId('unlock:wallet-session-auth-method-revocation-after'),
        issuedAtMs: fixture.session.createdAtMs + 4,
      }),
    ).rejects.toThrow();
    await expect(
      service.redeemHostedWalletSeamsSessionExchange({
        exchangeCode: delayedExchange.exchangeCode,
        nonce: delayedExchange.nonce,
        appOrigin: fixture.session.origin,
        walletOrigin,
        curve: 'ed25519',
        redeemedAtMs: fixture.session.createdAtMs + 4,
      }),
    ).resolves.toEqual({ kind: 'wallet_session_unavailable' });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM opaque_wallet_session_tokens
            WHERE namespace = ? AND tenant_id = ?`,
        )
        .bind(namespace, fixture.session.tenantId)
        .first<{ readonly count?: unknown }>(),
    ).resolves.toMatchObject({ count: 0 });

    await service.revokeReusableWalletSessionsForAuthMethod({
      tenantId: fixture.session.tenantId,
      walletId: fixture.authority.walletId,
      walletAuthMethodId: fixture.authorityRef.walletAuthMethodId,
      nowMs: fixture.session.createdAtMs + 5,
    });

    await expect(
      service.readWalletSessionAuthorizationByMint({
        ...issuance,
        nowMs: fixture.session.createdAtMs + 4,
      }),
    ).rejects.toThrow();
    const rows = await temporary.database
      .prepare(
        `SELECT session.lifecycle_kind AS session_lifecycle,
                quota.lifecycle_kind AS quota_lifecycle,
                quota.remaining_uses
           FROM reusable_wallet_sessions AS session
           JOIN authorization_wallet_session_quotas AS quota
             ON quota.namespace = session.namespace
            AND quota.tenant_id = session.tenant_id
            AND quota.wallet_session_id = session.wallet_session_id
          WHERE session.namespace = ?
            AND session.tenant_id = ?
            AND session.wallet_auth_method_id = ?`,
      )
      .bind(namespace, fixture.session.tenantId, fixture.authorityRef.walletAuthMethodId)
      .all<{
        readonly session_lifecycle: string;
        readonly quota_lifecycle: string;
        readonly remaining_uses: number;
      }>();
    expect(rows.results).toEqual([
      {
        session_lifecycle: 'superseded',
        quota_lifecycle: 'exhausted',
        remaining_uses: 0,
      },
    ]);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

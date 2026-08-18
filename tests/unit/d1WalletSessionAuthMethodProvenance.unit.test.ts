import { expect, test } from '@playwright/test';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { parseReusableWalletSessionMintId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseWalletAuthMethodId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import { buildPasskeyWalletSessionIssuanceFixture } from './helpers/authorizationCore.fixtures';

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

test('stores the issuing auth method and refuses a read under a different one', async () => {
  // Every part of this was broken at once by a bad bind list: the value was
  // appended to a statement with no placeholder for it, the insert reserved a
  // column it never bound, and no reader selected the column back. Row counts
  // and replay equality all still passed. Only asserting the exact stored
  // value, and refusing a mismatched read, catches that shape of mistake.
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const service = createService(temporary.database, 'wallet-session-provenance');
    const fixture = await buildPasskeyWalletSessionIssuanceFixture({
      tenantId: 'tenant-wallet-session-provenance',
      principalId: 'principal-wallet-session-provenance',
      walletId: 'wallet-session-provenance-wallet',
      credentialIdB64u: 'credential-wallet-session-provenance',
      rpId: 'example.test',
      origin: 'https://app.example.test',
      expiresAtMs: 1_900_000_100_000,
    });
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
      .bind('wallet-session-provenance', fixture.session.tenantId, String(mintId))
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

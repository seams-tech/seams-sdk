import { expect, test } from '@playwright/test';
import { parseWalletAuthAuthorityRef } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorization,
} from '../../packages/wallet-server/src/authorization/domain';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import type { D1DatabaseLike } from '../../packages/wallet-server/src/storage/tenantRoute';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWalletAuthMethodId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  buildRevokedLinkedDeviceAuthMethodV1,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';

const signerMigrations = listD1MigrationFiles('d1-signer');
const TEST_SCOPE = {
  namespace: 'wallet-auth-method-revocation-test',
  orgId: 'tenant:management',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

async function countRows(database: D1DatabaseLike, table: string): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count ?? 0);
}

function buildRecoverySourceAuthMethod(
  source: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>,
) {
  const walletAuthMethodId = parseWalletAuthMethodId('wallet-auth-method:recovery-source');
  if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId: source.authMethod.walletId,
    walletAuthorityId: source.authMethod.walletAuthorityId,
    kind: 'passkey',
    status: 'active',
    rpId: source.authMethod.rpId,
    credentialIdB64u: source.authMethod.credentialIdB64u,
    credentialPublicKeyB64u: source.authMethod.credentialPublicKeyB64u,
    counter: source.authMethod.counter,
    createdAtMs: source.authMethod.createdAtMs,
    updatedAtMs: source.authMethod.updatedAtMs,
    activatedAtMs: source.authMethod.activatedAtMs,
  });
  if (record.kind !== 'passkey' || record.status !== 'active') {
    throw new Error('recovery source auth method fixture is not active');
  }
  return record;
}

test('recovery revocation fences the exact source Wallet Session atomically', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const source = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'recovery-session-source',
      permissions: fullOwnerPermissionsForManagementFixture(),
      provenance: 'wallet_registration',
    });
    const sourceAuthMethod = buildRecoverySourceAuthMethod(source);
    const authMethods = new D1WalletAuthMethodStore({
      database: temporary.database,
      ...TEST_SCOPE,
      ensureSchema: false,
    });
    await authMethods.putV2(sourceAuthMethod);

    const authority = parseWalletAuthAuthorityRef({
      kind: 'wallet_auth_authority_ref',
      walletId: String(sourceAuthMethod.walletId),
      authorityDigest: String(source.authority.authorityDigestB64u),
      walletAuthMethodId: String(sourceAuthMethod.walletAuthMethodId),
    });
    if (!authority) throw new Error('source authority fixture is invalid');
    const session = buildWalletSessionAuthorization({
      tenantId: source.issuedSession.session.tenantId,
      principalId: source.issuedSession.session.principalId,
      walletId: source.issuedSession.session.walletId,
      authority,
      mintId: source.issuedSession.session.mintId,
      authorizationId: source.issuedSession.session.authorizationId,
      walletSessionId: source.issuedSession.session.walletSessionId,
      quotaId: source.issuedSession.session.quotaId,
      createdAtMs: source.issuedSession.session.createdAtMs,
      expiresAtMs: source.issuedSession.session.expiresAtMs,
    });
    const quota = buildActiveWalletSessionQuota({
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletSessionId: session.walletSessionId,
      quotaId: session.quotaId,
      remainingUses: 10,
      expiresAtMs: session.expiresAtMs,
    });
    const authorization = new CloudflareD1AuthorizationStore({
      database: temporary.database,
      namespace: TEST_SCOPE.namespace,
      walletSignerScope: TEST_SCOPE,
    });
    await authorization.putWalletSessionAuthorization({ session, quota });
    await temporary.database
      .prepare(
        `INSERT INTO opaque_wallet_session_tokens (
          namespace,
          tenant_id,
          token_hash,
          curve,
          wallet_session_id,
          binding_json
        ) VALUES (?, ?, ?, 'ed25519', ?, '{}')`,
      )
      .bind(
        TEST_SCOPE.namespace,
        session.tenantId,
        'source-session-token-hash',
        session.walletSessionId,
      )
      .run();

    const revokedAtMs = 4_000;
    await temporary.database.batch(
      authMethods.preparePasskeyRecoveryV2RevocationStatements({
        expected: sourceAuthMethod,
        record: buildRevokedLinkedDeviceAuthMethodV1(sourceAuthMethod, revokedAtMs),
        revokedAtMs,
      }),
    );

    await expect(countRows(temporary.database, 'opaque_wallet_session_tokens')).resolves.toBe(0);
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind, wallet_auth_method_id
             FROM reusable_wallet_sessions
            WHERE namespace = ? AND tenant_id = ? AND wallet_session_id = ?`,
        )
        .bind(TEST_SCOPE.namespace, session.tenantId, session.walletSessionId)
        .first(),
    ).resolves.toEqual({
      lifecycle_kind: 'superseded',
      wallet_auth_method_id: String(sourceAuthMethod.walletAuthMethodId),
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind, remaining_uses
             FROM authorization_wallet_session_quotas
            WHERE namespace = ? AND tenant_id = ? AND quota_id = ?`,
        )
        .bind(TEST_SCOPE.namespace, session.tenantId, session.quotaId)
        .first(),
    ).resolves.toEqual({ lifecycle_kind: 'exhausted', remaining_uses: 0 });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

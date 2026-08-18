import { expect, test } from '@playwright/test';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import {
  buildVerifiedWalletSessionPasskeyFactorResult,
} from '../../packages/wallet-server/src/authorization/factorEvidence';
import { parseVerifiedOwnerProofId } from '../../packages/wallet-server/src/authorization/domain';
import {
  parseAuthFactorId,
  parseReusableWalletSessionMintId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseWalletId, parseWebAuthnCredentialIdB64u } from '../../packages/shared-ts/src/utils/domainIds';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import { buildPasskeyWalletSessionIssuanceFixture } from './helpers/authorizationCore.fixtures';

const signerMigrations = listD1MigrationFiles('d1-signer');

test('one owner proof mints both curve tokens for one Wallet Session and rejects another scope', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'owner-proof-multi-curve';
    const store = new CloudflareD1AuthorizationStore({
      database: temporary.database,
      namespace,
      walletSignerScope: {
        namespace,
        orgId: 'test-org',
        projectId: 'test-project',
        envId: 'test-env',
      },
    });
    const service = new AuthorizationService({
      policy: capabilityPolicyPort,
      sessions: store,
      evidence: store,
      grants: store,
      authorizedOperations: store,
      audit: store,
    });
    const fixture = await buildPasskeyWalletSessionIssuanceFixture({
      tenantId: 'tenant-owner-proof',
      principalId: 'principal-owner-proof',
      walletId: 'wallet-owner-proof',
      credentialIdB64u: 'credential-owner-proof',
      rpId: 'example.test',
      origin: 'https://app.example.test',
      expiresAtMs: 1_900_000_100_000,
    });
    const walletId = required(parseWalletId(fixture.authority.walletId));
    const proof = await service.buildVerifiedOwnerProof({
      purpose: 'wallet_session',
      proofId: parseVerifiedOwnerProofId('owner-proof-multi-curve-proof'),
      factor: buildVerifiedWalletSessionPasskeyFactorResult({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId,
        authorityRef: fixture.authorityRef,
        requestOrigin: fixture.session.origin,
        audience: fixture.session.origin,
        factorId: required(parseAuthFactorId('passkey:owner-proof-multi-curve')),
        credentialIdB64u: required(parseWebAuthnCredentialIdB64u('credential-owner-proof')),
        assertionDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7))),
        verifiedAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.expiresAtMs - 1,
      }),
    });
    const session = await service.issueReusableWalletSession({
      tenantId: fixture.session.tenantId,
      principalId: fixture.session.principalId,
      walletId,
      authority: fixture.authorityRef,
      mintId: required(parseReusableWalletSessionMintId('unlock:owner-proof-multi-curve')),
      remainingUses: 3,
      issuedAtMs: fixture.session.createdAtMs + 1,
      expiresAtMs: fixture.session.expiresAtMs,
    });
    const common = {
      proof,
      tenantId: fixture.session.tenantId,
      authorizationId: session.session.authorizationId,
      walletSessionId: session.quota.walletSessionId,
      quotaId: session.quota.quotaId,
      expiresAtMs: session.session.expiresAtMs,
      consumedAtMs: fixture.session.createdAtMs + 2,
      binding: { walletId: String(walletId) },
    } as const;
    await expect(
      service.issueOpaqueWalletSessionToken({ ...common, curve: 'ed25519' }),
    ).resolves.toMatchObject({ kind: 'opaque_wallet_session_token', curve: 'ed25519' });
    await expect(
      service.issueOpaqueWalletSessionToken({ ...common, curve: 'ecdsa' }),
    ).resolves.toMatchObject({ kind: 'opaque_wallet_session_token', curve: 'ecdsa' });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM verified_owner_proof_consumptions
            WHERE namespace = ? AND tenant_id = ? AND proof_id = ?`,
        )
        .bind(namespace, fixture.session.tenantId, proof.proofId)
        .first<{ readonly count?: unknown }>(),
    ).resolves.toMatchObject({ count: 1 });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM opaque_wallet_session_tokens
            WHERE namespace = ? AND tenant_id = ? AND wallet_session_id = ?`,
        )
        .bind(namespace, fixture.session.tenantId, session.quota.walletSessionId)
        .first<{ readonly count?: unknown }>(),
    ).resolves.toMatchObject({ count: 2 });

    const otherSession = await service.issueReusableWalletSession({
      tenantId: fixture.session.tenantId,
      principalId: fixture.session.principalId,
      walletId,
      authority: fixture.authorityRef,
      mintId: required(parseReusableWalletSessionMintId('unlock:owner-proof-other-scope')),
      remainingUses: 3,
      issuedAtMs: fixture.session.createdAtMs + 3,
      expiresAtMs: fixture.session.expiresAtMs,
    });
    await expect(
      service.issueOpaqueWalletSessionToken({
        ...common,
        walletSessionId: otherSession.quota.walletSessionId,
        authorizationId: otherSession.session.authorizationId,
        quotaId: otherSession.quota.quotaId,
        curve: 'ed25519',
      }),
    ).rejects.toThrow('owner proof has already been consumed');
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

function required<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error?: { readonly message?: string } },
): T {
  if (!result.ok) throw new Error(result.error?.message ?? 'owner proof fixture value is invalid');
  return result.value;
}

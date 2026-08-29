import { expect, test } from '@playwright/test';
import {
  AuthorizationService,
  parseOpaqueOwnerWalletSessionBinding,
  type OpaqueOwnerWalletSessionBinding,
} from '../../packages/wallet-server/src/authorization/service';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { buildVerifiedWalletSessionPasskeyFactorResult } from '../../packages/wallet-server/src/authorization/factorEvidence';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorization,
  parseVerifiedOwnerProofId,
} from '../../packages/wallet-server/src/authorization/domain';
import {
  parseAuthFactorId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionMintId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import { buildPasskeyWalletSessionIssuanceFixture } from './helpers/authorizationCore.fixtures';
import { insertWalletAuthMethod } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { makeRouterAbEcdsaDerivationNormalSigningStateFixture } from './helpers/ecdsaSessionRecordVariants.fixtures';

const signerMigrations = listD1MigrationFiles('d1-signer');

type WalletSessionBindingIdentity = {
  readonly authorizationId: string;
  readonly walletSessionId: string;
  readonly quotaId: string;
  readonly expiresAtMs: number;
};

function ownerWalletSessionBinding(input: {
  readonly fixture: Awaited<ReturnType<typeof buildPasskeyWalletSessionIssuanceFixture>>;
  readonly identity: WalletSessionBindingIdentity;
  readonly curve: 'ed25519' | 'ecdsa';
}): OpaqueOwnerWalletSessionBinding {
  const { fixture, identity } = input;
  const base = {
    kind: 'opaque_owner_wallet_session_binding_v1' as const,
    walletId: String(fixture.authority.walletId),
    thresholdSessionId: 'threshold-session-owner-proof',
    authorizationId: identity.authorizationId,
    walletSessionId: identity.walletSessionId,
    quotaId: identity.quotaId,
    relayerKeyId: 'relayer-owner-proof',
    participantIds: [1, 2],
    thresholdExpiresAtMs: identity.expiresAtMs,
    subjectId: String(fixture.authority.walletId),
    keyManifestDigestB64u: base64UrlEncode(new Uint8Array(32).fill(9)),
  } as const;
  const raw =
    input.curve === 'ed25519'
      ? {
          ...base,
          curve: 'ed25519' as const,
          nearAccountId: 'near-owner-proof',
          nearEd25519SigningKeyId: 'near-key-owner-proof',
          authority: fixture.authority,
          runtimePolicyScope: {
            orgId: 'test-org',
            projectId: 'test-project',
            envId: 'test-env',
            signingRootVersion: 'test-root',
          },
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1' as const,
            signingWorkerId: 'relayer-owner-proof',
          },
        }
      : {
          ...base,
          curve: 'ecdsa' as const,
          authorizationSessionId: 'ecdsa-authorization-session-owner-proof',
          keyHandle: 'ecdsa-key-handle-owner-proof',
          walletAuthAuthorityRef: fixture.authorityRef,
          authSource: {
            kind: 'passkey' as const,
            credentialIdB64u: String(fixture.authority.factor.credentialIdB64u),
          },
          routerAbEcdsaDerivationNormalSigning:
            makeRouterAbEcdsaDerivationNormalSigningStateFixture({
              walletId: String(fixture.authority.walletId),
            }),
        };
  const parsed = parseOpaqueOwnerWalletSessionBinding(raw);
  if (!parsed) throw new Error(`invalid ${input.curve} owner Wallet Session binding fixture`);
  return parsed;
}

async function seedLegacyWalletSession(input: {
  readonly database: Parameters<typeof applyD1MigrationFiles>[0];
  readonly namespace: string;
  readonly session: ReturnType<typeof buildWalletSessionAuthorization>;
  readonly quota: ReturnType<typeof buildActiveWalletSessionQuota>;
}): Promise<{
  readonly session: ReturnType<typeof buildWalletSessionAuthorization>;
  readonly quota: ReturnType<typeof buildActiveWalletSessionQuota>;
}> {
  await input.database
    .prepare(
      `INSERT INTO authorization_wallet_session_quotas (
         namespace,
         tenant_id,
         quota_id,
         wallet_session_id,
         principal_id,
         remaining_uses,
         lifecycle_kind,
         expires_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
    )
    .bind(
      input.namespace,
      input.quota.tenantId,
      input.quota.quotaId,
      input.quota.walletSessionId,
      input.quota.principalId,
      input.quota.remainingUses,
      input.quota.expiresAtMs,
    )
    .run();
  await input.database
    .prepare(
      `INSERT INTO reusable_wallet_sessions (
         namespace,
         tenant_id,
         authorization_id,
         wallet_session_id,
         principal_id,
         wallet_id,
         authority_digest,
         wallet_auth_method_id,
         mint_id,
         quota_id,
         lifecycle_kind,
         created_at_ms,
         expires_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
    )
    .bind(
      input.namespace,
      input.session.tenantId,
      input.session.authorizationId,
      input.session.walletSessionId,
      input.session.principalId,
      input.session.walletId,
      input.session.authority.authorityDigest,
      input.session.authority.walletAuthMethodId,
      input.session.mintId,
      input.session.quotaId,
      input.session.createdAtMs,
      input.session.expiresAtMs,
    )
    .run();
  return { session: input.session, quota: input.quota };
}

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
      walletAuthMethodId: 'wallet-auth-method:owner-proof',
      credentialIdB64u: 'credential-owner-proof',
      rpId: 'example.test',
      origin: 'https://app.example.test',
      expiresAtMs: 1_900_000_100_000,
    });
    await insertWalletAuthMethod({
      database: temporary.database,
      namespace,
      orgId: 'test-org',
      projectId: 'test-project',
      envId: 'test-env',
      record: {
        kind: 'passkey',
        walletAuthMethodId: String(fixture.authority.bindingId),
        walletAuthorityId: 'wallet-authority:owner-proof',
        walletId: String(fixture.authority.walletId),
        rpId: String(fixture.authority.verifier.rpId),
        credentialIdB64u: String(fixture.authority.factor.credentialIdB64u),
        credentialPublicKeyB64u: 'credential-public-key-owner-proof',
        counter: 0,
        createdAtMs: fixture.session.createdAtMs,
        updatedAtMs: fixture.session.createdAtMs,
      },
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
    const session = await seedLegacyWalletSession({
      database: temporary.database,
      namespace,
      session: buildWalletSessionAuthorization({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId,
        authority: fixture.authorityRef,
        mintId: required(parseWalletSessionMintId('unlock:owner-proof-multi-curve')),
        authorizationId: required(
          parseWalletSessionAuthorizationId('authorization:owner-proof-multi-curve'),
        ),
        walletSessionId: required(parseWalletSessionId('wallet-session:owner-proof-multi-curve')),
        quotaId: required(parseMpcWalletSigningQuotaId('quota:owner-proof-multi-curve')),
        createdAtMs: fixture.session.createdAtMs + 1,
        expiresAtMs: fixture.session.expiresAtMs,
      }),
      quota: buildActiveWalletSessionQuota({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletSessionId: required(parseWalletSessionId('wallet-session:owner-proof-multi-curve')),
        quotaId: required(parseMpcWalletSigningQuotaId('quota:owner-proof-multi-curve')),
        remainingUses: 3,
        expiresAtMs: fixture.session.expiresAtMs,
      }),
    });
    const common = {
      proof,
      tenantId: fixture.session.tenantId,
      authorizationId: session.session.authorizationId,
      walletSessionId: session.quota.walletSessionId,
      quotaId: session.quota.quotaId,
      expiresAtMs: session.session.expiresAtMs,
      consumedAtMs: fixture.session.createdAtMs + 2,
    } as const;
    const ed25519Binding = ownerWalletSessionBinding({
      fixture,
      identity: {
        authorizationId: String(session.session.authorizationId),
        walletSessionId: String(session.quota.walletSessionId),
        quotaId: String(session.quota.quotaId),
        expiresAtMs: session.session.expiresAtMs,
      },
      curve: 'ed25519',
    });
    const ecdsaBinding = ownerWalletSessionBinding({
      fixture,
      identity: {
        authorizationId: String(session.session.authorizationId),
        walletSessionId: String(session.quota.walletSessionId),
        quotaId: String(session.quota.quotaId),
        expiresAtMs: session.session.expiresAtMs,
      },
      curve: 'ecdsa',
    });
    await expect(
      service.issueOpaqueWalletSessionToken({
        ...common,
        curve: 'ed25519',
        binding: ed25519Binding,
      }),
    ).resolves.toMatchObject({ kind: 'opaque_wallet_session_token', curve: 'ed25519' });
    await expect(
      service.issueOpaqueWalletSessionToken({
        ...common,
        curve: 'ecdsa',
        binding: ecdsaBinding,
      }),
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

    await temporary.database.batch([
      temporary.database
        .prepare(
          `UPDATE authorization_wallet_session_quotas
              SET remaining_uses = 0,
                  lifecycle_kind = 'exhausted'
            WHERE namespace = ? AND tenant_id = ? AND quota_id = ?`,
        )
        .bind(namespace, session.session.tenantId, session.quota.quotaId),
      temporary.database
        .prepare(
          `UPDATE reusable_wallet_sessions
              SET lifecycle_kind = 'superseded'
            WHERE namespace = ? AND tenant_id = ? AND wallet_session_id = ?`,
        )
        .bind(namespace, session.session.tenantId, session.session.walletSessionId),
    ]);
    const otherSession = await seedLegacyWalletSession({
      database: temporary.database,
      namespace,
      session: buildWalletSessionAuthorization({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletId,
        authority: fixture.authorityRef,
        mintId: required(parseWalletSessionMintId('unlock:owner-proof-other-scope')),
        authorizationId: required(
          parseWalletSessionAuthorizationId('authorization:owner-proof-other-scope'),
        ),
        walletSessionId: required(parseWalletSessionId('wallet-session:owner-proof-other-scope')),
        quotaId: required(parseMpcWalletSigningQuotaId('quota:owner-proof-other-scope')),
        createdAtMs: fixture.session.createdAtMs + 3,
        expiresAtMs: fixture.session.expiresAtMs,
      }),
      quota: buildActiveWalletSessionQuota({
        tenantId: fixture.session.tenantId,
        principalId: fixture.session.principalId,
        walletSessionId: required(parseWalletSessionId('wallet-session:owner-proof-other-scope')),
        quotaId: required(parseMpcWalletSigningQuotaId('quota:owner-proof-other-scope')),
        remainingUses: 3,
        expiresAtMs: fixture.session.expiresAtMs,
      }),
    });
    const otherEd25519Binding = ownerWalletSessionBinding({
      fixture,
      identity: {
        authorizationId: String(otherSession.session.authorizationId),
        walletSessionId: String(otherSession.quota.walletSessionId),
        quotaId: String(otherSession.quota.quotaId),
        expiresAtMs: otherSession.session.expiresAtMs,
      },
      curve: 'ed25519',
    });
    await expect(
      service.issueOpaqueWalletSessionToken({
        ...common,
        walletSessionId: otherSession.quota.walletSessionId,
        authorizationId: otherSession.session.authorizationId,
        quotaId: otherSession.quota.quotaId,
        curve: 'ed25519',
        binding: otherEd25519Binding,
      }),
    ).rejects.toThrow('owner proof has already been consumed');
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error?: { readonly message?: string } },
): T {
  if (!result.ok) throw new Error(result.error?.message ?? 'owner proof fixture value is invalid');
  return result.value;
}

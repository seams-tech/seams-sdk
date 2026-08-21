import { expect, test } from '@playwright/test';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import { D1WalletAuthorityStore } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { parseSessionOrigin } from '../../packages/wallet-server/src/authorization/domain';
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
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

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

type ActiveAuthorityFixture = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
};

function requiredParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

async function buildActiveAuthorityFixture(label: string): Promise<{
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly pendingAuthority: import('@shared/authorization/walletAuthority').PendingWalletAuthorityV1;
  readonly pendingAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'pending_local_install' }>;
}> {
  const walletId = requiredParsed(parseWalletId(`wallet:v2-${label}`));
  const authorityId = requiredParsed(parseWalletAuthorityId(`authority:v2-${label}`));
  const deviceId = requiredParsed(parseDeviceId(`device:v2-${label}`));
  const rpId = requiredParsed(parseWebAuthnRpId('example.test'));
  const credentialIdB64u = requiredParsed(
    parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(17))),
  );
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: String(walletId),
        walletKeyId: `wallet-key:v2-${label}`,
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(18)),
      },
    ],
  });
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest,
    materialActivations: {
      keyFamilies: ['ed25519'],
      ed25519: buildMpcMaterialActivationRefFixture(`v2-${label}`),
    },
  });
  const signerActivationSetDigestB64u = parseDigestB64u(
    await computeWalletSignerActivationSetDigestB64u(signerActivations),
  );
  const fixedAuthorityDigest = parseDigestB64u(
    base64UrlEncode(new Uint8Array(32).fill(19)),
  );
  const pendingDraft = buildPendingWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: fixedAuthorityDigest,
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u: fixedAuthorityDigest,
  });
  const pendingAuthority = buildPendingWalletAuthorityV1({
    kind: pendingDraft.kind,
    authorityId: pendingDraft.authorityId,
    walletId: pendingDraft.walletId,
    principal: pendingDraft.principal,
    provenance: pendingDraft.provenance,
    permissions: pendingDraft.permissions,
    signerActivations: pendingDraft.signerActivations,
    signerActivationSetDigestB64u: pendingDraft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(pendingDraft)),
    revocationEpoch: pendingDraft.revocationEpoch,
    createdAtMs: pendingDraft.createdAtMs,
    updatedAtMs: pendingDraft.updatedAtMs,
    state: pendingDraft.state,
    localInstallPackageSetDigestB64u: pendingDraft.localInstallPackageSetDigestB64u,
  });
  const activeDraft = buildActiveWalletAuthorityV1({
    kind: pendingAuthority.kind,
    authorityId: pendingAuthority.authorityId,
    walletId: pendingAuthority.walletId,
    principal: pendingAuthority.principal,
    provenance: pendingAuthority.provenance,
    permissions: pendingAuthority.permissions,
    signerActivations: pendingAuthority.signerActivations,
    signerActivationSetDigestB64u: pendingAuthority.signerActivationSetDigestB64u,
    authorityDigestB64u: fixedAuthorityDigest,
    revocationEpoch: pendingAuthority.revocationEpoch,
    createdAtMs: pendingAuthority.createdAtMs,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  });
  const authority = buildActiveWalletAuthorityV1({
    kind: activeDraft.kind,
    authorityId: activeDraft.authorityId,
    walletId: activeDraft.walletId,
    principal: activeDraft.principal,
    provenance: activeDraft.provenance,
    permissions: activeDraft.permissions,
    signerActivations: activeDraft.signerActivations,
    signerActivationSetDigestB64u: activeDraft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(activeDraft)),
    revocationEpoch: activeDraft.revocationEpoch,
    createdAtMs: activeDraft.createdAtMs,
    updatedAtMs: activeDraft.updatedAtMs,
    state: activeDraft.state,
    activatedAtMs: activeDraft.activatedAtMs,
  });
  const walletAuthMethodId = requiredWalletAuthMethodId(
    `passkey:${rpId}:${credentialIdB64u}`,
  );
  const pendingAuthMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'pending_local_install',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(20)),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: pendingAuthMethod.credentialPublicKeyB64u,
    counter: pendingAuthMethod.counter,
    createdAtMs: pendingAuthMethod.createdAtMs,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
  return { authority, authMethod, pendingAuthority, pendingAuthMethod };
}

async function seedActiveAuthority(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  namespace: string,
  label: string,
): Promise<ActiveAuthorityFixture> {
  const fixture = await buildActiveAuthorityFixture(label);
  const store = new D1WalletAuthorityStore({
    database,
    scope: {
      namespace,
      orgId: 'test-org',
      projectId: 'test-project',
      envId: 'test-env',
    },
    ensureSchema: false,
  });
  await store.commitPendingAuthority({
    authority: fixture.pendingAuthority,
    authMethod: fixture.pendingAuthMethod,
  });
  const activated = await store.activatePendingAuthority({
    pendingAuthority: fixture.pendingAuthority,
    activeAuthority: fixture.authority,
    pendingAuthMethod: fixture.pendingAuthMethod,
    activeAuthMethod: fixture.authMethod,
  });
  if (activated.kind !== 'activated') {
    throw new Error(`authority fixture activation failed: ${activated.kind}`);
  }
  return { authority: fixture.authority, authMethod: fixture.authMethod };
}

function authorityWithProvenance(
  authority: ActiveWalletAuthorityV1,
  authorityDigestB64u: DigestB64u,
  revocationEpoch: number,
): ActiveWalletAuthorityV1 {
  return buildActiveWalletAuthorityV1({
    kind: authority.kind,
    authorityId: authority.authorityId,
    walletId: authority.walletId,
    principal: authority.principal,
    provenance: authority.provenance,
    permissions: authority.permissions,
    signerActivations: authority.signerActivations,
    signerActivationSetDigestB64u: authority.signerActivationSetDigestB64u,
    authorityDigestB64u,
    revocationEpoch,
    createdAtMs: authority.createdAtMs,
    updatedAtMs: authority.updatedAtMs,
    state: authority.state,
    activatedAtMs: authority.activatedAtMs,
  });
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

test('issues V2 Wallet Sessions only for exact active authority provenance', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-v2-provenance';
    const service = createService(temporary.database, namespace);
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'session');
    const input = {
      tenantId: requiredParsed(parseTenantId('tenant:v2-session')),
      principalId: requiredParsed(parsePrincipalId('principal:v2-session')),
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:v2-session'),
      remainingUses: 3,
      issuedAtMs: 300,
      expiresAtMs: 400,
    };
    const issued = await service.issueWalletSessionAuthorizationV2(input);
    expect(issued.session.authorityId).toBe(fixture.authority.authorityId);
    expect(issued.session.walletAuthMethodId).toBe(fixture.authMethod.walletAuthMethodId);
    expect(issued.session.capabilitySubjects.length).toBeGreaterThan(0);

    await expect(service.issueWalletSessionAuthorizationV2(input)).resolves.toEqual(issued);
    await expect(
      service.readWalletSessionAuthorizationV2ByAuthorizationId({
        expected: issued.session,
        nowMs: 301,
      }),
    ).resolves.toEqual(issued);

    const otherMethodId = requiredWalletAuthMethodId(
      'passkey:example.test:other-v2-session-method',
    );
    const otherDigest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(21)));
    const driftInputs = [
      { ...input, walletAuthMethodId: otherMethodId },
      {
        ...input,
        authority: authorityWithProvenance(fixture.authority, otherDigest, 0),
      },
      {
        ...input,
        authority: authorityWithProvenance(fixture.authority, fixture.authority.authorityDigestB64u, 1),
      },
    ];
    for (const driftInput of driftInputs) {
      await expect(service.issueWalletSessionAuthorizationV2(driftInput)).rejects.toThrow(
        /V2 Wallet Session|provenance|replay/,
      );
    }

    await temporary.database
      .prepare(
        `UPDATE wallet_session_authorizations_v2
            SET retired_at_ms = ?
          WHERE namespace = ? AND tenant_id = ? AND mint_id = ?`,
      )
      .bind(399, namespace, input.tenantId, input.mintId)
      .run();
    await expect(
      service.readWalletSessionAuthorizationV2ByMint({
        expected: issued.session,
        nowMs: 301,
      }),
    ).rejects.toThrow(/retired/);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

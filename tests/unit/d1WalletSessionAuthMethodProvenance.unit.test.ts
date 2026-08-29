import { expect, test } from '@playwright/test';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildRevokedWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildAuthorizationGrantRef,
  buildNearEd25519MpcOperationRef,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseDeviceId,
} from '@shared/authorization/capabilityKinds';
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
  type WalletId,
} from '@shared/utils/domainIds';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { buildCapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import {
  buildAuthorizedOperation,
  buildPersistedActiveWalletSessionAuthorizationV2,
} from '../../packages/wallet-server/src/authorization/domain';
import { D1WalletAuthorityStore } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
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
  const store = createAuthorizationStore(database, namespace);
  return new AuthorizationService({
    policy: capabilityPolicyPort,
    sessions: store,
    evidence: store,
    grants: store,
    authorizedOperations: store,
    audit: store,
  });
}

function createAuthorizationStore(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  namespace: string,
): CloudflareD1AuthorizationStore {
  return new CloudflareD1AuthorizationStore({
    database,
    namespace,
    walletSignerScope: {
      namespace,
      orgId: 'test-org',
      projectId: 'test-project',
      envId: 'test-env',
    },
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

async function digestOpaqueCredentialForTest(value: string): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(value)));
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

async function buildActiveAuthorityFixture(
  label: string,
  input: { readonly walletAuthMethodId?: WalletAuthMethodId } = {},
): Promise<{
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly pendingAuthority: import('@shared/authorization/walletAuthority').PendingWalletAuthorityV1;
  readonly pendingAuthMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly status: 'pending_local_install' }
  >;
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
  const fixedAuthorityDigest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(19)));
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
  const walletAuthMethodId =
    input.walletAuthMethodId ?? requiredWalletAuthMethodId(`passkey:${rpId}:${credentialIdB64u}`);
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
  input: { readonly walletAuthMethodId?: WalletAuthMethodId } = {},
): Promise<ActiveAuthorityFixture> {
  const fixture = await buildActiveAuthorityFixture(label, input);
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
  updatedAtMs = authority.updatedAtMs,
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
    updatedAtMs,
    state: authority.state,
    activatedAtMs: authority.activatedAtMs,
  });
}

test('issues a registration session for the server-allocated active auth method id', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'registration-server-allocated-session';
    const walletAuthMethodId = requiredWalletAuthMethodId(
      'wallet-auth-method:registration-server-allocated',
    );
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'registration', {
      walletAuthMethodId,
    });
    const service = createService(temporary.database, namespace);
    const authority = buildPasskeyWalletAuthAuthority({
      walletId: fixture.authMethod.walletId,
      rpId: fixture.authMethod.rpId,
      credentialIdB64u: fixture.authMethod.credentialIdB64u,
    });
    const canonicalAuthorityRef = await walletAuthAuthorityRef({ authority });
    const registrationAuthorityRef = {
      ...canonicalAuthorityRef,
      walletAuthMethodId,
    } as const;
    const input = {
      tenantId: requiredParsed(parseTenantId('tenant:registration-session')),
      principalId: requiredParsed(parsePrincipalId('principal:registration-session')),
      walletId: authority.walletId,
      authority: registrationAuthorityRef,
      mintId: requiredMintId('registration:server-allocated-session'),
      remainingUses: 3,
      issuedAtMs: 300,
      expiresAtMs: 400,
    } as const;

    const issued = await service.issueReusableWalletSession(input);
    expect(issued.session.authority.walletAuthMethodId).toBe(walletAuthMethodId);
    await expect(service.issueReusableWalletSession(input)).resolves.toEqual(issued);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('promotes a registration session into the exact V2 authority projection', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'registration-v2-session-promotion';
    const walletAuthMethodId = requiredWalletAuthMethodId(
      'wallet-auth-method:registration-v2-promotion',
    );
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'registration-v2', {
      walletAuthMethodId,
    });
    const service = createService(temporary.database, namespace);
    const authority = buildPasskeyWalletAuthAuthority({
      walletId: fixture.authMethod.walletId,
      rpId: fixture.authMethod.rpId,
      credentialIdB64u: fixture.authMethod.credentialIdB64u,
    });
    const canonicalAuthorityRef = await walletAuthAuthorityRef({ authority });
    const registrationAuthorityRef = {
      ...canonicalAuthorityRef,
      walletAuthMethodId,
    } as const;
    const issued = await service.issueReusableWalletSession({
      tenantId: requiredParsed(parseTenantId('tenant:registration-v2-promotion')),
      principalId: requiredParsed(parsePrincipalId('principal:registration-v2-promotion')),
      walletId: authority.walletId,
      authority: registrationAuthorityRef,
      mintId: requiredMintId('registration:v2-promotion'),
      remainingUses: 3,
      issuedAtMs: 300,
      expiresAtMs: 400,
    });
    const promoted = await service.issueWalletSessionAuthorizationV2FromReusableSession({
      reusableWalletSession: issued,
      authority: fixture.authority,
      walletAuthMethodId,
    });

    expect(promoted.session.authorizationId).toBe(issued.session.authorizationId);
    expect(promoted.session.walletSessionId).toBe(issued.session.walletSessionId);
    expect(promoted.session.quotaId).toBe(issued.session.quotaId);
    expect(promoted.session.authorityId).toBe(fixture.authority.authorityId);
    expect(promoted.session.walletAuthMethodId).toBe(walletAuthMethodId);
    expect(promoted.session.authorityDigestB64u).toBe(fixture.authority.authorityDigestB64u);
    await expect(
      service.readWalletSessionAuthorizationV2ByIdentity({
        tenantId: promoted.session.tenantId,
        walletId: promoted.session.walletId,
        walletSessionId: promoted.session.walletSessionId,
        authorizationId: promoted.session.authorizationId,
        nowMs: 301,
      }),
    ).resolves.toEqual(promoted);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('keeps exact V2 session identity readable for device inventory after quota exhaustion', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'device-inventory-exhausted-session';
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'device-inventory');
    const service = createService(temporary.database, namespace);
    const issued = await service.issueWalletSessionAuthorizationV2({
      tenantId: requiredParsed(parseTenantId('tenant:device-inventory')),
      principalId: requiredParsed(parsePrincipalId('principal:device-inventory')),
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:device-inventory'),
      remainingUses: 1,
      issuedAtMs: 300,
      expiresAtMs: 400,
    });
    await temporary.database
      .prepare(
        `UPDATE authorization_wallet_session_quotas
            SET lifecycle_kind = 'exhausted', remaining_uses = 0
          WHERE namespace = ? AND tenant_id = ? AND quota_id = ?`,
      )
      .bind(namespace, issued.session.tenantId, issued.session.quotaId)
      .run();

    await expect(
      service.readWalletSessionAuthorizationV2ByIdentity({
        tenantId: issued.session.tenantId,
        walletId: issued.session.walletId,
        walletSessionId: issued.session.walletSessionId,
        authorizationId: issued.session.authorizationId,
        nowMs: 301,
      }),
    ).rejects.toThrow('Stored V2 Wallet Session quota is no longer active');
    await expect(
      createAuthorizationStore(
        temporary.database,
        namespace,
      ).readActiveWalletSessionAuthorizationV2ByIdentity({
        tenantId: issued.session.tenantId,
        walletId: issued.session.walletId,
        walletSessionId: issued.session.walletSessionId,
        authorizationId: issued.session.authorizationId,
        nowMs: 301,
      }),
    ).resolves.toEqual(issued.session);
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
        authority: authorityWithProvenance(
          fixture.authority,
          fixture.authority.authorityDigestB64u,
          1,
        ),
      },
    ];
    for (const driftInput of driftInputs) {
      await expect(service.issueWalletSessionAuthorizationV2(driftInput)).rejects.toThrow(
        /V2 Wallet Session|provenance|replay/,
      );
    }
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('direct V2 issuance is replay-stable and exhausts the same-method predecessor atomically', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-v2-direct-issuance';
    const service = createService(temporary.database, namespace);
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'direct-issuance');
    const firstInput = {
      tenantId: requiredParsed(parseTenantId('tenant:v2-direct-issuance')),
      principalId: requiredParsed(parsePrincipalId('principal:v2-direct-issuance')),
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:v2-direct-issuance:first'),
      remainingUses: 3,
      issuedAtMs: 300,
      expiresAtMs: 500,
    } as const;

    const first = await service.issueDirectWalletSessionAuthorizationV2(firstInput);
    expect(first.kind).toBe('issued');
    if (first.kind !== 'issued') throw new Error('first direct issuance did not issue');

    const replay = await service.issueDirectWalletSessionAuthorizationV2(firstInput);
    expect(replay).toMatchObject({
      kind: 'already_committed',
      authorizationId: first.session.authorizationId,
      walletSessionId: first.session.walletSessionId,
      quotaId: first.session.quotaId,
      next: 'unlock_exact_method',
    });

    const losingDigest = await digestOpaqueCredentialForTest('concurrent-losing-credential');
    const concurrentLoser = await createAuthorizationStore(
      temporary.database,
      namespace,
    ).commitDirectWalletSessionAuthorizationV2({
      persisted: buildPersistedActiveWalletSessionAuthorizationV2({
        session: first.session,
        quota: first.quota,
        primaryOperationCredentialDigestB64u: losingDigest,
      }),
    });
    expect(concurrentLoser).toMatchObject({
      kind: 'already_committed',
      committed: {
        session: first.session,
        primaryOperationCredentialDigestB64u: await digestOpaqueCredentialForTest(
          first.operationCredential.token,
        ),
      },
    });

    const replacementInput = {
      ...firstInput,
      mintId: requiredMintId('unlock:v2-direct-issuance:replacement'),
      issuedAtMs: 350,
      expiresAtMs: 550,
    } as const;
    await temporary.database.exec(`
      CREATE TRIGGER r103f_fail_direct_v2_session_insert
      BEFORE INSERT ON wallet_session_authorizations_v2
      BEGIN
        SELECT RAISE(ABORT, 'injected direct V2 session insert failure');
      END;
    `);
    await expect(service.issueDirectWalletSessionAuthorizationV2(replacementInput)).rejects.toThrow(
      /injected direct V2 session insert failure/,
    );
    const afterFailedReplacement = await temporary.database
      .prepare(
        `SELECT
           (SELECT COUNT(*)
              FROM wallet_session_authorizations_v2
             WHERE namespace = ?
               AND tenant_id = ?
               AND wallet_id = ?
               AND authority_id = ?
               AND wallet_auth_method_id = ?) AS session_count,
           (SELECT COUNT(*)
              FROM authorization_wallet_session_quotas
             WHERE namespace = ?
               AND tenant_id = ?) AS quota_count,
           session.retired_at_ms AS predecessor_retired_at_ms,
           quota.remaining_uses AS predecessor_remaining_uses,
           quota.lifecycle_kind AS predecessor_lifecycle_kind
         FROM wallet_session_authorizations_v2 AS session
         JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = session.namespace
          AND quota.tenant_id = session.tenant_id
          AND quota.quota_id = session.quota_id
        WHERE session.namespace = ?
          AND session.tenant_id = ?
          AND session.mint_id = ?`,
      )
      .bind(
        namespace,
        firstInput.tenantId,
        String(firstInput.walletId),
        String(firstInput.authority.authorityId),
        String(firstInput.walletAuthMethodId),
        namespace,
        firstInput.tenantId,
        namespace,
        firstInput.tenantId,
        String(firstInput.mintId),
      )
      .first<{
        readonly session_count: number;
        readonly quota_count: number;
        readonly predecessor_retired_at_ms: number | null;
        readonly predecessor_remaining_uses: number;
        readonly predecessor_lifecycle_kind: string;
      }>();
    expect(afterFailedReplacement).toEqual({
      session_count: 1,
      quota_count: 1,
      predecessor_retired_at_ms: null,
      predecessor_remaining_uses: 3,
      predecessor_lifecycle_kind: 'active',
    });
    await temporary.database.exec('DROP TRIGGER r103f_fail_direct_v2_session_insert;');

    const replacement = await service.issueDirectWalletSessionAuthorizationV2(replacementInput);
    expect(replacement.kind).toBe('issued');
    if (replacement.kind !== 'issued') throw new Error('replacement direct issuance did not issue');

    const replacementCredentialBeforeReplay = await temporary.database
      .prepare(
        `SELECT operation_credential_hash
           FROM wallet_session_authorizations_v2
          WHERE namespace = ? AND tenant_id = ? AND authorization_id = ?`,
      )
      .bind(namespace, firstInput.tenantId, String(replacement.session.authorizationId))
      .first<{ readonly operation_credential_hash: string }>();
    const replacementReplay = await service.issueDirectWalletSessionAuthorizationV2(
      replacementInput,
    );
    expect(replacementReplay).toMatchObject({
      kind: 'already_committed',
      authorizationId: replacement.session.authorizationId,
      walletSessionId: replacement.session.walletSessionId,
      quotaId: replacement.session.quotaId,
      next: 'unlock_exact_method',
    });
    const replacementCredentialAfterReplay = await temporary.database
      .prepare(
        `SELECT operation_credential_hash
           FROM wallet_session_authorizations_v2
          WHERE namespace = ? AND tenant_id = ? AND authorization_id = ?`,
      )
      .bind(namespace, firstInput.tenantId, String(replacement.session.authorizationId))
      .first<{ readonly operation_credential_hash: string }>();
    expect(replacementCredentialBeforeReplay).toEqual({
      operation_credential_hash: await digestOpaqueCredentialForTest(
        replacement.operationCredential.token,
      ),
    });
    expect(replacementCredentialAfterReplay).toEqual(replacementCredentialBeforeReplay);

    const rows = await temporary.database
      .prepare(
        `SELECT
           session.mint_id,
           session.retired_at_ms,
           quota.remaining_uses,
           quota.lifecycle_kind
         FROM wallet_session_authorizations_v2 AS session
         JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = session.namespace
          AND quota.tenant_id = session.tenant_id
          AND quota.quota_id = session.quota_id
        WHERE session.namespace = ?
          AND session.tenant_id = ?
          AND session.wallet_id = ?
          AND session.authority_id = ?
          AND session.wallet_auth_method_id = ?
        ORDER BY session.issued_at_ms`,
      )
      .bind(
        namespace,
        firstInput.tenantId,
        String(firstInput.walletId),
        String(firstInput.authority.authorityId),
        String(firstInput.walletAuthMethodId),
      )
      .all<{
        readonly mint_id: string;
        readonly retired_at_ms: number | null;
        readonly remaining_uses: number;
        readonly lifecycle_kind: string;
      }>();
    expect(rows.results).toEqual([
      {
        mint_id: String(firstInput.mintId),
        retired_at_ms: 350,
        remaining_uses: 0,
        lifecycle_kind: 'exhausted',
      },
      {
        mint_id: String(replacement.session.mintId),
        retired_at_ms: null,
        remaining_uses: 3,
        lifecycle_kind: 'active',
      },
    ]);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('issues and rereads one exact operation credential, refusing wrong, rotated, revoked, and expired bindings', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-v2-operation-credential';
    const service = createService(temporary.database, namespace);
    const fixture = await seedActiveAuthority(
      temporary.database,
      namespace,
      'operation-credential',
    );
    const input = {
      tenantId: requiredParsed(parseTenantId('tenant:v2-operation-credential')),
      principalId: requiredParsed(parsePrincipalId('principal:v2-operation-credential')),
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:v2-operation-credential'),
      remainingUses: 3,
      issuedAtMs: 300,
      expiresAtMs: 400,
    } as const;
    const issued = await service.issueWalletSessionAuthorizationV2(input);

    const credential = await service.issueWalletSessionAuthorizationV2OperationCredential({
      session: issued.session,
    });
    expect(credential.kind).toBe('opaque_wallet_session_operation_credential_v1');
    expect(credential.token).toMatch(/^wst_[A-Za-z0-9_-]{43}$/);
    expect(credential.walletSessionId).toBe(issued.session.walletSessionId);
    await expect(
      temporary.database
        .prepare(
          `SELECT operation_credential_hash
             FROM wallet_session_authorizations_v2
            WHERE namespace = ? AND tenant_id = ? AND authorization_id = ?`,
        )
        .bind(namespace, input.tenantId, String(issued.session.authorizationId))
        .first<{ readonly operation_credential_hash?: unknown }>(),
    ).resolves.toEqual({
      operation_credential_hash: await digestOpaqueCredentialForTest(credential.token),
    });
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId: input.tenantId,
        token: credential.token,
        nowMs: 301,
      }),
    ).resolves.toEqual(issued);
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId: input.tenantId,
        token: `${credential.token}x`,
        nowMs: 301,
      }),
    ).resolves.toBeNull();

    const rotated = await service.issueWalletSessionAuthorizationV2OperationCredential({
      session: issued.session,
    });
    expect(rotated.token).not.toBe(credential.token);
    expect(rotated.walletSessionId).toBe(credential.walletSessionId);
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId: input.tenantId,
        token: credential.token,
        nowMs: 301,
      }),
    ).resolves.toBeNull();
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId: input.tenantId,
        token: rotated.token,
        nowMs: 301,
      }),
    ).resolves.toEqual(issued);
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId: input.tenantId,
        token: rotated.token,
        nowMs: issued.session.expiresAtMs,
      }),
    ).rejects.toThrow(/expired/);

    const revokedAuthorityDigest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(99)));
    const revokedAuthority = buildRevokedWalletAuthorityV1({
      kind: 'wallet_authority_v1',
      authorityId: fixture.authority.authorityId,
      walletId: fixture.authority.walletId,
      principal: fixture.authority.principal,
      provenance: fixture.authority.provenance,
      permissions: fixture.authority.permissions,
      signerActivations: fixture.authority.signerActivations,
      signerActivationSetDigestB64u: fixture.authority.signerActivationSetDigestB64u,
      authorityDigestB64u: revokedAuthorityDigest,
      revocationEpoch: fixture.authority.revocationEpoch + 1,
      createdAtMs: fixture.authority.createdAtMs,
      updatedAtMs: 401,
      state: 'revoked' as const,
      activatedAtMs: fixture.authority.activatedAtMs,
      revokedAtMs: 401,
    });
    await temporary.database
      .prepare(
        `UPDATE wallet_authorities
            SET lifecycle_state = ?,
                authority_digest_b64u = ?,
                revocation_epoch = ?,
                record_json = ?,
                updated_at_ms = ?,
                revoked_at_ms = ?
          WHERE namespace = ? AND authority_id = ?`,
      )
      .bind(
        revokedAuthority.state,
        String(revokedAuthority.authorityDigestB64u),
        revokedAuthority.revocationEpoch,
        JSON.stringify(revokedAuthority),
        revokedAuthority.updatedAtMs,
        revokedAuthority.revokedAtMs,
        namespace,
        String(revokedAuthority.authorityId),
      )
      .run();
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId: input.tenantId,
        token: rotated.token,
        nowMs: 301,
      }),
    ).rejects.toThrow(/provenance|active/);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('refreshes an established V2 Wallet Session against an upgraded active authority without rotating identity', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-v2-authority-refresh';
    const walletAuthMethodId = requiredWalletAuthMethodId(
      'wallet-auth-method:v2-authority-refresh',
    );
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'authority-refresh', {
      walletAuthMethodId,
    });
    const service = createService(temporary.database, namespace);
    const walletAuthAuthority = buildPasskeyWalletAuthAuthority({
      walletId: fixture.authMethod.walletId,
      rpId: fixture.authMethod.rpId,
      credentialIdB64u: fixture.authMethod.credentialIdB64u,
    });
    const canonicalAuthorityRef = await walletAuthAuthorityRef({
      authority: walletAuthAuthority,
    });
    const reusableAuthorityRef = {
      ...canonicalAuthorityRef,
      walletAuthMethodId,
    } as const;
    const reusableWalletSession = await service.issueReusableWalletSession({
      tenantId: requiredParsed(parseTenantId('tenant:v2-authority-refresh')),
      principalId: requiredParsed(parsePrincipalId('principal:v2-authority-refresh')),
      walletId: fixture.authority.walletId,
      authority: reusableAuthorityRef,
      mintId: requiredMintId('unlock:v2-authority-refresh'),
      remainingUses: 3,
      issuedAtMs: 300,
      expiresAtMs: 400,
    });
    const established = await service.issueWalletSessionAuthorizationV2FromReusableSession({
      reusableWalletSession,
      authority: fixture.authority,
      walletAuthMethodId,
    });
    const operationCredential = await service.issueWalletSessionAuthorizationV2OperationCredential({
      session: established.session,
    });

    const upgradedAuthority = authorityWithProvenance(
      fixture.authority,
      parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(71))),
      fixture.authority.revocationEpoch,
      401,
    );
    await temporary.database
      .prepare(
        `UPDATE wallet_authorities
            SET lifecycle_state = ?,
                authority_digest_b64u = ?,
                revocation_epoch = ?,
                record_json = ?,
                updated_at_ms = ?
          WHERE namespace = ? AND authority_id = ?`,
      )
      .bind(
        upgradedAuthority.state,
        String(upgradedAuthority.authorityDigestB64u),
        upgradedAuthority.revocationEpoch,
        JSON.stringify(upgradedAuthority),
        upgradedAuthority.updatedAtMs,
        namespace,
        String(upgradedAuthority.authorityId),
      )
      .run();

    await expect(
      service.readWalletSessionAuthorizationV2ByIdentity({
        tenantId: established.session.tenantId,
        walletId: established.session.walletId,
        walletSessionId: established.session.walletSessionId,
        authorizationId: established.session.authorizationId,
        nowMs: 301,
      }),
    ).rejects.toThrow(/provenance/);

    const refreshed = await service.refreshWalletSessionAuthorizationV2FromReusableSession({
      reusableWalletSession,
      authority: upgradedAuthority,
      walletAuthMethodId,
    });

    expect({
      tenantId: refreshed.session.tenantId,
      principalId: refreshed.session.principalId,
      walletId: refreshed.session.walletId,
      authorityId: refreshed.session.authorityId,
      walletAuthMethodId: refreshed.session.walletAuthMethodId,
      mintId: refreshed.session.mintId,
      authorizationId: refreshed.session.authorizationId,
      walletSessionId: refreshed.session.walletSessionId,
      quotaId: refreshed.session.quotaId,
    }).toEqual({
      tenantId: established.session.tenantId,
      principalId: established.session.principalId,
      walletId: established.session.walletId,
      authorityId: established.session.authorityId,
      walletAuthMethodId: established.session.walletAuthMethodId,
      mintId: established.session.mintId,
      authorizationId: established.session.authorizationId,
      walletSessionId: established.session.walletSessionId,
      quotaId: established.session.quotaId,
    });
    expect(refreshed.session.authorityDigestB64u).toBe(upgradedAuthority.authorityDigestB64u);
    expect(refreshed.session.authorityRevocationEpoch).toBe(upgradedAuthority.revocationEpoch);
    expect(refreshed.quota).toEqual(established.quota);
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId: refreshed.session.tenantId,
        token: operationCredential.token,
        nowMs: 301,
      }),
    ).resolves.toEqual(refreshed);
    await expect(
      service.readWalletSessionAuthorizationV2ByIdentity({
        tenantId: refreshed.session.tenantId,
        walletId: refreshed.session.walletId,
        walletSessionId: refreshed.session.walletSessionId,
        authorizationId: refreshed.session.authorizationId,
        nowMs: 301,
      }),
    ).resolves.toEqual(refreshed);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('admits a V2 Wallet Session operation and replays against its exact source', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'authorized-operation-v2-claim';
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'v2-claim');
    const service = createService(temporary.database, namespace);
    const directIssue = await service.issueDirectWalletSessionAuthorizationV2({
      tenantId: requiredParsed(parseTenantId('tenant:v2-claim')),
      principalId: requiredParsed(parsePrincipalId('principal:v2-claim')),
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:v2-claim'),
      remainingUses: 2,
      issuedAtMs: 300,
      expiresAtMs: 400,
    });
    if (directIssue.kind !== 'issued') {
      throw new Error('V2 operation admission fixture did not issue its direct credential');
    }
    const session = {
      session: directIssue.session,
      quota: directIssue.quota,
    };
    const operation = buildCapabilityOperationEnvelope({
      tenantId: session.session.tenantId,
      principalId: session.session.principalId,
      capabilityId: requiredParsed(
        parseCapabilityId(
          String(fixture.authority.signerActivations.ed25519.materialActivation.capability),
        ),
      ),
      operationId: requiredParsed(parseCapabilityOperationId('operation:v2-claim')),
      operation: buildNearEd25519MpcOperationRef(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction),
      digests: {
        laneDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(81))),
        intentDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(82))),
        displayDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(83))),
      },
    });
    const claimInput = await buildAuthorizedOperation({
      tenantId: session.session.tenantId,
      authorizedOperationId: requiredParsed(
        parseAuthorizedOperationId('authorized-operation:v2-claim'),
      ),
      auditEventId: requiredParsed(parseAuthorizationAuditEventId('audit:v2-claim')),
      operation,
      authorization: {
        kind: 'authorization_grant',
        authorizationGrantRef: buildAuthorizationGrantRef(session.session.authorizationId),
      },
      quota: {
        kind: 'consume_reusable_wallet_session',
        quotaId: session.session.quotaId,
      },
      claimedAtMs: 301,
    });

    await expect(
      service.admitAuthorizedOperation({ operation: claimInput }),
    ).resolves.toMatchObject({
      kind: 'claimed',
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT remaining_uses, lifecycle_kind
             FROM authorization_wallet_session_quotas
            WHERE namespace = ? AND tenant_id = ? AND quota_id = ?`,
        )
        .bind(namespace, session.session.tenantId, session.session.quotaId)
        .first(),
    ).resolves.toEqual({ remaining_uses: 1, lifecycle_kind: 'active' });

    const retry = await buildAuthorizedOperation({
      ...claimInput,
      authorizedOperationId: requiredParsed(
        parseAuthorizedOperationId('authorized-operation:v2-claim-retry'),
      ),
      auditEventId: requiredParsed(parseAuthorizationAuditEventId('audit:v2-claim-retry')),
      claimedAtMs: 302,
    });
    await expect(service.admitAuthorizedOperation({ operation: retry })).resolves.toMatchObject({
      kind: 'operation_in_progress',
    });
    await expect(
      temporary.database
        .prepare(
          `SELECT remaining_uses
             FROM authorization_wallet_session_quotas
            WHERE namespace = ? AND tenant_id = ? AND quota_id = ?`,
        )
        .bind(namespace, session.session.tenantId, session.session.quotaId)
        .first(),
    ).resolves.toEqual({ remaining_uses: 1 });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

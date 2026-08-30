import { expect, test } from '@playwright/test';
import {
  buildFullOwnerPermissionsV1,
} from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
  type PendingWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import {
  parseDeviceId,
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionMintId,
  type PrincipalId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  D1WalletAuthorityStore,
  type D1WalletAuthorityStoreScope,
} from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import {
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  applyD1MigrationFiles,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { buildExactWalletSessionAuthorizationFixture } from './helpers/exactWalletSessionAuthorization.fixtures';
import { createCloudflareD1RouterApiAuthService } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { parseSessionOrigin } from '../../packages/wallet-server/src/authorization/domain';

const scope: D1WalletAuthorityStoreScope = {
  namespace: 'wallet-authority-store-test',
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'env-test',
};

const walletId = requireParsed(parseWalletId('wallet:authority-store-test'));
const fixedDigest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));

type AuthorityFixture = {
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly pendingAuthority: PendingWalletAuthorityV1;
  readonly activeAuthority: ActiveWalletAuthorityV1;
  readonly pendingAuthMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly status: 'pending_local_install' }
  >;
  readonly activeAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
};

type AuthorityFixtureOptions = {
  readonly label: string;
  readonly localInstallSeed?: number;
  readonly activeAtMs?: number;
};

type AuthorityTestDatabase = ReturnType<typeof createTemporaryD1Database>['database'];

function requireParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function buildActiveSiblingAuthMethod(
  fixture: AuthorityFixture,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: requireParsed(parseWalletAuthMethodId('auth-method:authority-sibling')),
    walletId: fixture.walletId,
    walletAuthorityId: fixture.authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: fixture.activeAuthMethod.rpId,
    credentialIdB64u: requireParsed(
      parseWebAuthnCredentialIdB64u('credential:authority-store-sibling'),
    ),
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(19)),
    counter: 0,
    createdAtMs: 21,
    updatedAtMs: 21,
    activatedAtMs: 21,
  });
}

async function readExactAuthoritySessionLifecycle(input: {
  readonly database: AuthorityTestDatabase;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
}) {
  return await input.database
    .prepare(
      `SELECT session.authority_id,
              session.wallet_auth_method_id,
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
          AND session.principal_id = ?
        ORDER BY session.authority_id, session.wallet_auth_method_id`,
    )
    .bind(scope.namespace, input.tenantId, input.principalId)
    .all<{
      readonly authority_id: string;
      readonly wallet_auth_method_id: string;
      readonly retired_at_ms: number | null;
      readonly remaining_uses: number;
      readonly lifecycle_kind: string;
    }>();
}

function buildEd25519SignerManifest(label: string): ReturnType<
  typeof parseExactAdministeredSignerManifestV1
> {
  return parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: String(walletId),
        walletKeyId: `wallet-key:authority-store-${label}`,
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(11)),
      },
    ],
  });
}

async function buildAuthorityFixture(
  options: AuthorityFixtureOptions,
): Promise<AuthorityFixture> {
  const authorityId = requireParsed(parseWalletAuthorityId(`authority:${options.label}`));
  const deviceId = requireParsed(parseDeviceId(`device:${options.label}`));
  const walletAuthMethodId = requireParsed(
    parseWalletAuthMethodId(`auth-method:authority-store-${options.label}`),
  );
  const rpId = requireParsed(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = requireParsed(
    parseWebAuthnCredentialIdB64u(`credential:authority-store-${options.label}`),
  );
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: buildEd25519SignerManifest(options.label),
    materialActivations: {
      keyFamilies: ['ed25519'],
      ed25519: buildMpcMaterialActivationRefFixture(
        `authority-store-${options.label}`,
      ),
    },
  });
  const signerActivationSetDigestB64u = await computeWalletSignerActivationSetDigestB64u(
    signerActivations,
  );
  const localInstallPackageSetDigestB64u = parseDigestB64u(
    base64UrlEncode(new Uint8Array(32).fill(options.localInstallSeed ?? 9)),
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
    authorityDigestB64u: fixedDigest,
    revocationEpoch: 0,
    createdAtMs: 10,
    updatedAtMs: 10,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u,
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
    authorityDigestB64u: parseDigestB64u(
      await computeWalletAuthorityDigestB64u(pendingDraft),
    ),
    revocationEpoch: pendingDraft.revocationEpoch,
    createdAtMs: pendingDraft.createdAtMs,
    updatedAtMs: pendingDraft.updatedAtMs,
    state: pendingDraft.state,
    localInstallPackageSetDigestB64u: pendingDraft.localInstallPackageSetDigestB64u,
  });
  const activeAtMs = options.activeAtMs ?? 20;
  const activeDraft = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId: pendingAuthority.authorityId,
    walletId: pendingAuthority.walletId,
    principal: pendingAuthority.principal,
    provenance: pendingAuthority.provenance,
    permissions: pendingAuthority.permissions,
    signerActivations: pendingAuthority.signerActivations,
    signerActivationSetDigestB64u: pendingAuthority.signerActivationSetDigestB64u,
    authorityDigestB64u: fixedDigest,
    revocationEpoch: pendingAuthority.revocationEpoch,
    createdAtMs: pendingAuthority.createdAtMs,
    updatedAtMs: activeAtMs,
    state: 'active',
    activatedAtMs: activeAtMs,
  });
  const activeAuthority = buildActiveWalletAuthorityV1({
    kind: activeDraft.kind,
    authorityId: activeDraft.authorityId,
    walletId: activeDraft.walletId,
    principal: activeDraft.principal,
    provenance: activeDraft.provenance,
    permissions: activeDraft.permissions,
    signerActivations: activeDraft.signerActivations,
    signerActivationSetDigestB64u: activeDraft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(
      await computeWalletAuthorityDigestB64u(activeDraft),
    ),
    revocationEpoch: activeDraft.revocationEpoch,
    createdAtMs: activeDraft.createdAtMs,
    updatedAtMs: activeDraft.updatedAtMs,
    state: activeDraft.state,
    activatedAtMs: activeDraft.activatedAtMs,
  });
  const pendingAuthMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'pending_local_install',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(12)),
    counter: 0,
    createdAtMs: 10,
    updatedAtMs: 10,
  });
  const activeAuthMethod = buildWalletAuthMethodRecordV2({
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
    updatedAtMs: activeAtMs,
    activatedAtMs: activeAtMs,
  });
  return {
    authorityId,
    walletId,
    pendingAuthority,
    activeAuthority,
    pendingAuthMethod,
    activeAuthMethod,
  };
}

function buildAdditionalPasskeyAuthMethod(
  fixture: AuthorityFixture,
  label: string,
  createdAtMs: number,
): Extract<WalletAuthMethodRecordV2, { readonly kind: 'passkey'; readonly status: 'active' }> {
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: requireParsed(parseWalletAuthMethodId(`wallet-auth-method:${label}`)),
    walletId: fixture.walletId,
    walletAuthorityId: fixture.authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: fixture.activeAuthMethod.rpId,
    credentialIdB64u: requireParsed(parseWebAuthnCredentialIdB64u(`credential:${label}`)),
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(createdAtMs)),
    counter: 0,
    createdAtMs,
    updatedAtMs: createdAtMs,
    activatedAtMs: createdAtMs,
  });
  if (record.kind !== 'passkey' || record.status !== 'active') {
    throw new Error('additional passkey auth-method fixture is invalid');
  }
  return record;
}

function pendingAuthorityWithPackageDigest(
  authority: PendingWalletAuthorityV1,
  localInstallPackageSetDigestB64u: PendingWalletAuthorityV1['localInstallPackageSetDigestB64u'],
): PendingWalletAuthorityV1 {
  return buildPendingWalletAuthorityV1({
    kind: authority.kind,
    authorityId: authority.authorityId,
    walletId: authority.walletId,
    principal: authority.principal,
    provenance: authority.provenance,
    permissions: authority.permissions,
    signerActivations: authority.signerActivations,
    signerActivationSetDigestB64u: authority.signerActivationSetDigestB64u,
    authorityDigestB64u: authority.authorityDigestB64u,
    revocationEpoch: authority.revocationEpoch,
    createdAtMs: authority.createdAtMs,
    updatedAtMs: authority.updatedAtMs,
    state: authority.state,
    localInstallPackageSetDigestB64u,
  });
}

function pendingAuthorityWithSignerActivations(
  authority: PendingWalletAuthorityV1,
  signerActivations: PendingWalletAuthorityV1['signerActivations'],
): PendingWalletAuthorityV1 {
  return buildPendingWalletAuthorityV1({
    kind: authority.kind,
    authorityId: authority.authorityId,
    walletId: authority.walletId,
    principal: authority.principal,
    provenance: authority.provenance,
    permissions: authority.permissions,
    signerActivations,
    signerActivationSetDigestB64u: authority.signerActivationSetDigestB64u,
    authorityDigestB64u: authority.authorityDigestB64u,
    revocationEpoch: authority.revocationEpoch,
    createdAtMs: authority.createdAtMs,
    updatedAtMs: authority.updatedAtMs,
    state: authority.state,
    localInstallPackageSetDigestB64u: authority.localInstallPackageSetDigestB64u,
  });
}

test('persists pending authority rows, replays exact input, and reports conflicts', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const store = new D1WalletAuthorityStore({
      database: temporary.database,
      scope,
      ensureSchema: false,
    });
    const fixture = await buildAuthorityFixture({ label: 'pending', localInstallSeed: 9 });

    await expect(
      store.commitPendingAuthority({
        authority: fixture.pendingAuthority,
        authMethod: fixture.pendingAuthMethod,
      }),
    ).resolves.toMatchObject({ kind: 'committed_wallet_authority_v1' });
    await expect(store.readById(fixture.authorityId)).resolves.toEqual(fixture.pendingAuthority);
    await expect(
      store.listForWallet({ walletId: fixture.walletId, limit: 10, cursor: null }),
    ).resolves.toEqual({ records: [fixture.pendingAuthority], nextCursor: null });

    await expect(
      store.commitPendingAuthority({
        authority: fixture.pendingAuthority,
        authMethod: fixture.pendingAuthMethod,
      }),
    ).resolves.toMatchObject({ kind: 'replayed' });

    const conflictingFixture = await buildAuthorityFixture({
      label: 'pending',
      localInstallSeed: 10,
    });
    await expect(
      store.commitPendingAuthority({
        authority: conflictingFixture.pendingAuthority,
        authMethod: conflictingFixture.pendingAuthMethod,
      }),
    ).resolves.toEqual({ kind: 'conflict', authorityId: fixture.authorityId });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('activates through the pending CAS, rejects conflicting activation, and replays exactly', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const store = new D1WalletAuthorityStore({
      database: temporary.database,
      scope,
      ensureSchema: false,
    });
    const fixture = await buildAuthorityFixture({ label: 'activation' });
    await store.commitPendingAuthority({
      authority: fixture.pendingAuthority,
      authMethod: fixture.pendingAuthMethod,
    });

    const packageDrift = pendingAuthorityWithPackageDigest(
      fixture.pendingAuthority,
      parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(13))),
    );
    await expect(
      store.activatePendingAuthority({
        pendingAuthority: packageDrift,
        activeAuthority: fixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.activeAuthMethod,
      }),
    ).resolves.toEqual({ kind: 'conflict', authorityId: fixture.authorityId });
    await expect(store.readById(fixture.authorityId)).resolves.toEqual(fixture.pendingAuthority);

    const signerDriftFixture = await buildAuthorityFixture({ label: 'activation-signer-drift' });
    const signerDrift = pendingAuthorityWithSignerActivations(
      fixture.pendingAuthority,
      signerDriftFixture.pendingAuthority.signerActivations,
    );
    await expect(
      store.activatePendingAuthority({
        pendingAuthority: signerDrift,
        activeAuthority: fixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.activeAuthMethod,
      }),
    ).rejects.toThrow('authority activation identities do not match');
    await expect(store.readById(fixture.authorityId)).resolves.toEqual(fixture.pendingAuthority);

    const activationResult = await store.activatePendingAuthority({
      pendingAuthority: fixture.pendingAuthority,
      activeAuthority: fixture.activeAuthority,
      pendingAuthMethod: fixture.pendingAuthMethod,
      activeAuthMethod: fixture.activeAuthMethod,
    });
    expect(activationResult).toMatchObject({ kind: 'activated' });

    const conflictingFixture = await buildAuthorityFixture({
      label: 'activation',
      activeAtMs: 21,
    });
    await expect(
      store.activatePendingAuthority({
        pendingAuthority: fixture.pendingAuthority,
        activeAuthority: conflictingFixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: conflictingFixture.activeAuthMethod,
      }),
    ).resolves.toEqual({ kind: 'conflict', authorityId: fixture.authorityId });
    await expect(store.readById(fixture.authorityId)).resolves.toEqual(fixture.activeAuthority);

    await expect(
      store.activatePendingAuthority({
        pendingAuthority: fixture.pendingAuthority,
        activeAuthority: fixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.activeAuthMethod,
      }),
    ).resolves.toMatchObject({ kind: 'replayed', authority: fixture.activeAuthority });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('revokes one authority method and protects the final active wallet method', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const store = new D1WalletAuthorityStore({
      database: temporary.database,
      scope,
      ensureSchema: false,
    });
    const first = await buildAuthorityFixture({ label: 'revoke-first' });
    const second = await buildAuthorityFixture({ label: 'revoke-second' });
    for (const fixture of [first, second]) {
      await store.commitPendingAuthority({
        authority: fixture.pendingAuthority,
        authMethod: fixture.pendingAuthMethod,
      });
      await store.activatePendingAuthority({
        pendingAuthority: fixture.pendingAuthority,
        activeAuthority: fixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.activeAuthMethod,
      });
    }
    const activeRows = await temporary.database
      .prepare(
        `SELECT wallet_auth_method_id, status
           FROM wallet_auth_methods
          WHERE wallet_id = ?
          ORDER BY wallet_auth_method_id`,
      )
      .bind(String(first.walletId))
      .all<{ readonly wallet_auth_method_id?: unknown; readonly status?: unknown }>();
    expect(activeRows.results).toHaveLength(2);
    expect(activeRows.results.every((row) => row.status === 'active')).toBe(true);

    await expect(
      store.revokeWalletAuthMethod({
        walletId: first.walletId,
        authorityId: first.authorityId,
        walletAuthMethodId: first.activeAuthMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: 0,
        requestedAtMs: 30,
      }),
    ).resolves.toMatchObject({
      kind: 'revoked_method',
      authMethod: { status: 'revoked', revokedAtMs: 30 },
      authority: { state: 'revoked', revocationEpoch: 1, revokedAtMs: 30 },
    });
    await expect(store.readById(first.authorityId)).resolves.toMatchObject({
      state: 'revoked',
      revocationEpoch: 1,
    });

    await expect(
      store.revokeWalletAuthMethod({
        walletId: second.walletId,
        authorityId: second.authorityId,
        walletAuthMethodId: second.activeAuthMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: 0,
        requestedAtMs: 31,
      }),
    ).resolves.toEqual({ kind: 'would_remove_last_wallet_auth_method' });
    await expect(store.readById(second.authorityId)).resolves.toMatchObject({
      state: 'active',
      revocationEpoch: 0,
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('authority session fence waits for the final sibling and preserves unrelated V2 sessions', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const authorityStore = new D1WalletAuthorityStore({
      database: temporary.database,
      scope,
      ensureSchema: false,
    });
    const authMethodStore = new D1WalletAuthMethodStore({
      database: temporary.database,
      ...scope,
      ensureSchema: false,
    });
    const authorizationStore = new CloudflareD1AuthorizationStore({
      database: temporary.database,
      namespace: scope.namespace,
      walletSignerScope: scope,
    });
    const target = await buildAuthorityFixture({ label: 'authority-session-target' });
    const unrelated = await buildAuthorityFixture({ label: 'authority-session-unrelated' });
    for (const fixture of [target, unrelated]) {
      await authorityStore.commitPendingAuthority({
        authority: fixture.pendingAuthority,
        authMethod: fixture.pendingAuthMethod,
      });
      await authorityStore.activatePendingAuthority({
        pendingAuthority: fixture.pendingAuthority,
        activeAuthority: fixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.activeAuthMethod,
      });
    }
    const siblingMethod = buildActiveSiblingAuthMethod(target);
    await authMethodStore.putV2(siblingMethod);

    const tenantId = requireParsed(parseTenantId(scope.orgId));
    const principalId = requireParsed(parsePrincipalId('principal:authority-session-fence'));
    const targetSession = buildExactWalletSessionAuthorizationFixture({
      label: 'authority-session-target',
      tenantId,
      principalId,
      authority: target.activeAuthority,
      walletAuthMethodId: target.activeAuthMethod.walletAuthMethodId,
      issuedAtMs: 25,
      expiresAtMs: 100,
      remainingUses: 3,
    });
    const siblingSession = buildExactWalletSessionAuthorizationFixture({
      label: 'authority-session-sibling',
      tenantId,
      principalId,
      authority: target.activeAuthority,
      walletAuthMethodId: siblingMethod.walletAuthMethodId,
      issuedAtMs: 26,
      expiresAtMs: 100,
      remainingUses: 4,
    });
    const unrelatedSession = buildExactWalletSessionAuthorizationFixture({
      label: 'authority-session-unrelated',
      tenantId,
      principalId,
      authority: unrelated.activeAuthority,
      walletAuthMethodId: unrelated.activeAuthMethod.walletAuthMethodId,
      issuedAtMs: 27,
      expiresAtMs: 100,
      remainingUses: 5,
    });
    const hostedTenantId = tenantId;
    const hostedPrincipalId = requireParsed(
      parsePrincipalId('principal:authority-hosted-revocation'),
    );
    const routerService = createCloudflareD1RouterApiAuthService({
      database: temporary.database,
      ...scope,
    });
    const hostedParent =
      await routerService.authorizationSessions.issueDirectWalletSessionAuthorizationV2({
        tenantId: hostedTenantId,
        principalId: hostedPrincipalId,
        walletId: target.walletId,
        authority: target.activeAuthority,
        walletAuthMethodId: target.activeAuthMethod.walletAuthMethodId,
        mintId: requireParsed(parseWalletSessionMintId('mint:authority-hosted-revocation')),
        remainingUses: 3,
        issuedAtMs: 25,
        expiresAtMs: 100,
      });
    expect(hostedParent.kind).toBe('issued');
    if (hostedParent.kind !== 'issued') throw new Error('hosted authority parent did not issue');
    const appOrigin = parseSessionOrigin('https://app.authority.example.test');
    const walletOrigin = parseSessionOrigin('https://wallet.authority.example.test');
    const hostedDelivery =
      await routerService.authorizationSessions.mintHostedWalletSeamsSessionExchange({
        authorization: hostedParent,
        appOrigin,
        walletOrigin,
        issuedAtMs: 26,
        expiresAtMs: 90,
      });
    const hostedCredential =
      await routerService.authorizationSessions.redeemHostedWalletSeamsSessionExchange({
        exchangeCode: hostedDelivery.exchangeCode,
        nonce: hostedDelivery.nonce,
        appOrigin,
        walletOrigin,
        redeemedAtMs: 27,
      });
    expect(hostedCredential.kind).toBe('redeemed');
    if (hostedCredential.kind !== 'redeemed')
      throw new Error('hosted authority child did not redeem');
    await routerService.authorizationSessions.mintHostedWalletSeamsSessionExchange({
      authorization: hostedParent,
      appOrigin,
      walletOrigin,
      issuedAtMs: 28,
      expiresAtMs: 90,
    });
    await authorizationStore.putWalletSessionAuthorizationV2(targetSession);
    await authorizationStore.putWalletSessionAuthorizationV2(siblingSession);
    await authorizationStore.putWalletSessionAuthorizationV2(unrelatedSession);

    await expect(
      authorityStore.revokeWalletAuthMethod({
        walletId: target.walletId,
        authorityId: target.authorityId,
        walletAuthMethodId: target.activeAuthMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: 0,
        requestedAtMs: 30,
        sessionRevocationStatements:
          authorizationStore.prepareRetireWalletSessionAuthorizationsV2ForAuthority({
            tenantId,
            walletId: target.walletId,
            authorityId: target.authorityId,
            nowMs: 30,
          }),
      }),
    ).resolves.toMatchObject({
      kind: 'revoked_method',
      authority: { state: 'active' },
    });
    expect(
      (
        await readExactAuthoritySessionLifecycle({
          database: temporary.database,
          tenantId,
          principalId,
        })
      ).results,
    ).toEqual([
      {
        authority_id: String(target.authorityId),
        wallet_auth_method_id: String(siblingMethod.walletAuthMethodId),
        retired_at_ms: null,
        remaining_uses: 4,
        lifecycle_kind: 'active',
      },
      {
        authority_id: String(target.authorityId),
        wallet_auth_method_id: String(target.activeAuthMethod.walletAuthMethodId),
        retired_at_ms: null,
        remaining_uses: 3,
        lifecycle_kind: 'active',
      },
      {
        authority_id: String(unrelated.authorityId),
        wallet_auth_method_id: String(unrelated.activeAuthMethod.walletAuthMethodId),
        retired_at_ms: null,
        remaining_uses: 5,
        lifecycle_kind: 'active',
      },
    ]);
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind, retired_at_ms
             FROM wallet_session_hosted_credentials_v2
            WHERE namespace = ? AND tenant_id = ? AND wallet_auth_method_id = ?`,
        )
        .bind(scope.namespace, hostedTenantId, String(target.activeAuthMethod.walletAuthMethodId))
        .first(),
    ).resolves.toEqual({ lifecycle_kind: 'active', retired_at_ms: null });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM wallet_session_hosted_exchange_codes_v2
            WHERE namespace = ? AND tenant_id = ? AND wallet_auth_method_id = ?
              AND lifecycle_kind = 'issued'`,
        )
        .bind(scope.namespace, hostedTenantId, String(target.activeAuthMethod.walletAuthMethodId))
        .first<{ readonly count?: unknown }>(),
    ).resolves.toEqual({ count: 1 });

    await expect(
      authorityStore.revokeWalletAuthMethod({
        walletId: target.walletId,
        authorityId: target.authorityId,
        walletAuthMethodId: siblingMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: 0,
        requestedAtMs: 31,
        sessionRevocationStatements:
          authorizationStore.prepareRetireWalletSessionAuthorizationsV2ForAuthority({
            tenantId,
            walletId: target.walletId,
            authorityId: target.authorityId,
            nowMs: 31,
          }),
      }),
    ).resolves.toMatchObject({
      kind: 'revoked_method',
      authority: { state: 'revoked', revocationEpoch: 1 },
    });
    expect(
      (
        await readExactAuthoritySessionLifecycle({
          database: temporary.database,
          tenantId,
          principalId,
        })
      ).results,
    ).toEqual([
      {
        authority_id: String(target.authorityId),
        wallet_auth_method_id: String(siblingMethod.walletAuthMethodId),
        retired_at_ms: 31,
        remaining_uses: 0,
        lifecycle_kind: 'exhausted',
      },
      {
        authority_id: String(target.authorityId),
        wallet_auth_method_id: String(target.activeAuthMethod.walletAuthMethodId),
        retired_at_ms: 31,
        remaining_uses: 0,
        lifecycle_kind: 'exhausted',
      },
      {
        authority_id: String(unrelated.authorityId),
        wallet_auth_method_id: String(unrelated.activeAuthMethod.walletAuthMethodId),
        retired_at_ms: null,
        remaining_uses: 5,
        lifecycle_kind: 'active',
      },
    ]);
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind, retired_at_ms
             FROM wallet_session_hosted_credentials_v2
            WHERE namespace = ? AND tenant_id = ? AND wallet_auth_method_id = ?`,
        )
        .bind(scope.namespace, hostedTenantId, String(target.activeAuthMethod.walletAuthMethodId))
        .first(),
    ).resolves.toEqual({ lifecycle_kind: 'retired', retired_at_ms: 31 });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM wallet_session_hosted_exchange_codes_v2
            WHERE namespace = ? AND tenant_id = ? AND wallet_auth_method_id = ?
              AND lifecycle_kind = 'issued'`,
        )
        .bind(scope.namespace, hostedTenantId, String(target.activeAuthMethod.walletAuthMethodId))
        .first<{ readonly count?: unknown }>(),
    ).resolves.toEqual({ count: 0 });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('rolls back method revocation when an atomic session fence fails', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const store = new D1WalletAuthorityStore({
      database: temporary.database,
      scope,
      ensureSchema: false,
    });
    const first = await buildAuthorityFixture({ label: 'atomic-revoke-first' });
    const second = await buildAuthorityFixture({ label: 'atomic-revoke-second' });
    for (const fixture of [first, second]) {
      await store.commitPendingAuthority({
        authority: fixture.pendingAuthority,
        authMethod: fixture.pendingAuthMethod,
      });
      await store.activatePendingAuthority({
        pendingAuthority: fixture.pendingAuthority,
        activeAuthority: fixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.activeAuthMethod,
      });
    }

    const invalidSessionFence = temporary.database
      .prepare('INSERT INTO wallet_authorities (namespace) VALUES (?)')
      .bind(scope.namespace);
    await expect(
      store.revokeWalletAuthMethod({
        walletId: first.walletId,
        authorityId: first.authorityId,
        walletAuthMethodId: first.activeAuthMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: 0,
        requestedAtMs: 35,
        sessionRevocationStatements: [invalidSessionFence],
      }),
    ).resolves.toEqual({ kind: 'conflict' });

    const method = await temporary.database
      .prepare('SELECT status FROM wallet_auth_methods WHERE wallet_auth_method_id = ?')
      .bind(String(first.activeAuthMethod.walletAuthMethodId))
      .first<{ readonly status?: unknown }>();
    expect(method?.status).toBe('active');
    await expect(store.readById(first.authorityId)).resolves.toMatchObject({
      state: 'active',
      revocationEpoch: 0,
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('serializes competing revocations of the final two wallet methods', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const store = new D1WalletAuthorityStore({
      database: temporary.database,
      scope,
      ensureSchema: false,
    });
    const first = await buildAuthorityFixture({ label: 'revoke-race-first' });
    const second = await buildAuthorityFixture({ label: 'revoke-race-second' });
    for (const fixture of [first, second]) {
      await store.commitPendingAuthority({
        authority: fixture.pendingAuthority,
        authMethod: fixture.pendingAuthMethod,
      });
      await store.activatePendingAuthority({
        pendingAuthority: fixture.pendingAuthority,
        activeAuthority: fixture.activeAuthority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.activeAuthMethod,
      });
    }

    const results = await Promise.all([
      store.revokeWalletAuthMethod({
        walletId: first.walletId,
        authorityId: first.authorityId,
        walletAuthMethodId: first.activeAuthMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: 0,
        requestedAtMs: 40,
      }),
      store.revokeWalletAuthMethod({
        walletId: second.walletId,
        authorityId: second.authorityId,
        walletAuthMethodId: second.activeAuthMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: 0,
        requestedAtMs: 41,
      }),
    ]);
    expect(results.filter((result) => result.kind === 'revoked_method')).toHaveLength(1);
    expect(
      results.filter(
        (result) =>
          result.kind === 'conflict' || result.kind === 'would_remove_last_wallet_auth_method',
      ),
    ).toHaveLength(1);

    const rows = await temporary.database
      .prepare(
        `SELECT status
           FROM wallet_auth_methods
          WHERE wallet_id = ?
          ORDER BY wallet_auth_method_id`,
      )
      .bind(String(first.walletId))
      .all<{ readonly status?: unknown }>();
    expect(rows.results).toHaveLength(2);
    expect(rows.results.filter((row) => row.status === 'active')).toHaveLength(1);
    expect(rows.results.filter((row) => row.status === 'revoked')).toHaveLength(1);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('add-auth commit rejects a source method revoked after ceremony start', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const authorityStore = new D1WalletAuthorityStore({
      database: temporary.database,
      scope,
      ensureSchema: false,
    });
    const authMethodStore = new D1WalletAuthMethodStore({
      database: temporary.database,
      ...scope,
      ensureSchema: false,
    });
    const source = await buildAuthorityFixture({ label: 'add-auth-source' });
    await authorityStore.commitPendingAuthority({
      authority: source.pendingAuthority,
      authMethod: source.pendingAuthMethod,
    });
    await authorityStore.activatePendingAuthority({
      pendingAuthority: source.pendingAuthority,
      activeAuthority: source.activeAuthority,
      pendingAuthMethod: source.pendingAuthMethod,
      activeAuthMethod: source.activeAuthMethod,
    });

    const sourceGuard = authMethodStore.prepareActiveV2SourceGuardStatements({
      walletId: source.walletId,
      walletAuthMethodId: source.activeAuthMethod.walletAuthMethodId,
      walletAuthorityId: source.authorityId,
      authorityDigestB64u: source.activeAuthority.authorityDigestB64u,
      authorityRevocationEpoch: source.activeAuthority.revocationEpoch,
    });
    const sibling = buildAdditionalPasskeyAuthMethod(source, 'add-auth-sibling', 25);
    await expect(
      authMethodStore.insertActiveV2Atomically({
        record: sibling,
        prerequisiteStatements: sourceGuard,
      }),
    ).resolves.toBe(true);

    await expect(
      authorityStore.revokeWalletAuthMethod({
        walletId: source.walletId,
        authorityId: source.authorityId,
        walletAuthMethodId: source.activeAuthMethod.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: source.activeAuthority.revocationEpoch,
        requestedAtMs: 30,
      }),
    ).resolves.toMatchObject({ kind: 'revoked_method' });

    const lateTarget = buildAdditionalPasskeyAuthMethod(source, 'add-auth-late-target', 35);
    await expect(
      authMethodStore.insertActiveV2Atomically({
        record: lateTarget,
        prerequisiteStatements: sourceGuard,
      }),
    ).resolves.toBe(false);
    await expect(
      authMethodStore.readByIdV2({ walletAuthMethodId: lateTarget.walletAuthMethodId }),
    ).resolves.toBeNull();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

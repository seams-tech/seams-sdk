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
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
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
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  D1WalletAuthorityStore,
  type D1WalletAuthorityStoreScope,
} from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import {
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  applyD1MigrationFiles,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

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

function requireParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
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

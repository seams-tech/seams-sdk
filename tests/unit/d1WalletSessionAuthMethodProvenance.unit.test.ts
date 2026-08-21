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
  const walletAuthMethodId = requiredWalletAuthMethodId(`passkey:${rpId}:${credentialIdB64u}`);
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

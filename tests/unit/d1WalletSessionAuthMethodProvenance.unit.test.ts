import { expect, test } from '@playwright/test';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
  type PendingWalletAuthorityV1,
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
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
} from '@shared/utils/domainIds';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { buildCapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/createFetchRouter';
import {
  handleHostedWalletSessionExchangeIssue,
  handleHostedWalletSessionExchangeRedeem,
} from '../../packages/wallet-server/src/router/transport/fetch/routes/sessions';
import {
  buildAuthorizedOperation,
  buildPersistedActiveWalletSessionAuthorizationV2,
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseSessionOrigin,
} from '../../packages/wallet-server/src/authorization/domain';
import { D1WalletAuthorityStore } from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { prepareD1WalletAuthMethodV2PutStatement } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

/** Wallet Sessions record which auth method issued them for precise revocation. */
const signerMigrations = listD1MigrationFiles('d1-signer');

type AuthorizationScope = {
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

const DEFAULT_AUTHORIZATION_SCOPE: AuthorizationScope = {
  orgId: 'test-org',
  projectId: 'test-project',
  envId: 'test-env',
};

function createService(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  namespace: string,
  scope: AuthorizationScope = DEFAULT_AUTHORIZATION_SCOPE,
): AuthorizationService {
  const store = createAuthorizationStore(database, namespace, scope);
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
  scope: AuthorizationScope = DEFAULT_AUTHORIZATION_SCOPE,
): CloudflareD1AuthorizationStore {
  return new CloudflareD1AuthorizationStore({
    database,
    namespace,
    walletSignerScope: {
      namespace,
      ...scope,
    },
  });
}

function requiredMintId(value: string) {
  const parsed = parseWalletSessionMintId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requiredWalletAuthMethodId(value: string) {
  const parsed = parseWalletAuthMethodId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function rowCount(
  database: Parameters<typeof applyD1MigrationFiles>[0],
  table: 'wallet_session_hosted_credentials_v2',
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
    .first<{ readonly count?: unknown }>();
  return Number(row?.count);
}

function hostedRouteContext(input: {
  readonly pathname: string;
  readonly request: Request;
  readonly hostedWalletOrigins: readonly string[];
  readonly authorizationSessions: Record<string, unknown>;
}): FetchRouterApiContext {
  return {
    method: 'POST',
    pathname: input.pathname,
    request: input.request,
    opts: { hostedWalletOrigins: [...input.hostedWalletOrigins] },
    service: { authorizationSessions: input.authorizationSessions },
  } as unknown as FetchRouterApiContext;
}

async function digestOpaqueCredentialForTest(value: string): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(value)));
}

type ActiveAuthorityFixture = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActivePasskeyAuthMethod;
};

type ActivePasskeyAuthMethod = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

function requiredParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function buildSiblingActivePasskeyAuthMethod(
  source: ActivePasskeyAuthMethod,
  credentialByte: number,
): ActivePasskeyAuthMethod {
  const credentialIdB64u = requiredParsed(
    parseWebAuthnCredentialIdB64u(base64UrlEncode(new Uint8Array(32).fill(credentialByte))),
  );
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: requiredWalletAuthMethodId(
      `passkey:${source.rpId}:${credentialIdB64u}`,
    ),
    walletId: source.walletId,
    walletAuthorityId: source.walletAuthorityId,
    kind: 'passkey',
    status: 'active',
    rpId: source.rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(credentialByte + 1)),
    counter: 0,
    createdAtMs: source.createdAtMs,
    updatedAtMs: source.updatedAtMs,
    activatedAtMs: source.activatedAtMs,
  });
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

async function recoveredAuthority(
  authority: ActiveWalletAuthorityV1,
): Promise<ActiveWalletAuthorityV1> {
  const recoveryProvenance = {
    kind: 'wallet_recovery' as const,
    recoveryOperationId: requiredParsed(
      parseWalletRecoveryOperationId('wallet-recovery:v2-direct-issuance'),
    ),
    continuityAuthorityId: requiredParsed(
      parseWalletAuthorityId('authority:v2-recovery-continuity'),
    ),
  };
  const draft = buildActiveWalletAuthorityV1({
    kind: authority.kind,
    authorityId: authority.authorityId,
    walletId: authority.walletId,
    principal: authority.principal,
    provenance: recoveryProvenance,
    permissions: authority.permissions,
    signerActivations: authority.signerActivations,
    signerActivationSetDigestB64u: authority.signerActivationSetDigestB64u,
    authorityDigestB64u: authority.authorityDigestB64u,
    revocationEpoch: authority.revocationEpoch,
    createdAtMs: authority.createdAtMs,
    updatedAtMs: authority.updatedAtMs,
    state: authority.state,
    activatedAtMs: authority.activatedAtMs,
  });
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

async function pendingRecoveredAuthority(
  authority: ActiveWalletAuthorityV1,
  localInstallPackageSetDigestB64u: DigestB64u,
): Promise<PendingWalletAuthorityV1> {
  const draft = buildPendingWalletAuthorityV1({
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
    updatedAtMs: authority.createdAtMs,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u,
  });
  return buildPendingWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    localInstallPackageSetDigestB64u: draft.localInstallPackageSetDigestB64u,
  });
}

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

test('hosted V2 child shares quota, expires, and retires with its parent', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'hosted-wallet-v2-exchange';
    const service = createService(temporary.database, namespace);
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'hosted-exchange');
    const tenantId = requiredParsed(parseTenantId('tenant:hosted-exchange'));
    const principalId = requiredParsed(parsePrincipalId('principal:hosted-exchange'));
    const firstInput = {
      tenantId,
      principalId,
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:hosted-exchange:first'),
      remainingUses: 1,
      issuedAtMs: 300,
      expiresAtMs: 700,
    } as const;
    const first = await service.issueDirectWalletSessionAuthorizationV2(firstInput);
    expect(first.kind).toBe('issued');
    if (first.kind !== 'issued') throw new Error('hosted parent issuance did not issue');

    const appOrigin = parseSessionOrigin('https://app.hosted.example.test');
    const walletOrigin = parseSessionOrigin('https://wallet.hosted.example.test');
    const delivery = await service.mintHostedWalletSeamsSessionExchange({
      authorization: { session: first.session, quota: first.quota },
      appOrigin,
      walletOrigin,
      issuedAtMs: 350,
      expiresAtMs: 900,
    });
    expect(delivery.kind).toBe('hosted_wallet_session_exchange_delivery_v2');
    expect(delivery.expiresAtMs).toBe(first.session.expiresAtMs);
    const storedExchange = await temporary.database
      .prepare(
        `SELECT code_hash, nonce_digest, lifecycle_kind
           FROM wallet_session_hosted_exchange_codes_v2
          WHERE namespace = ? AND tenant_id = ?`,
      )
      .bind(namespace, tenantId)
      .first<{
        readonly code_hash: string;
        readonly nonce_digest: string;
        lifecycle_kind: string;
      }>();
    expect(storedExchange).toMatchObject({ lifecycle_kind: 'issued' });
    expect(storedExchange?.code_hash).not.toBe(delivery.exchangeCode);
    expect(storedExchange?.nonce_digest).not.toBe(delivery.nonce);

    await expect(
      service.redeemHostedWalletSeamsSessionExchange({
        exchangeCode: delivery.exchangeCode,
        nonce: delivery.nonce,
        appOrigin,
        walletOrigin: parseSessionOrigin('https://wrong.hosted.example.test'),
        redeemedAtMs: 351,
      }),
    ).resolves.toEqual({ kind: 'wallet_origin_mismatch' });
    const redeemed = await service.redeemHostedWalletSeamsSessionExchange({
      exchangeCode: delivery.exchangeCode,
      nonce: delivery.nonce,
      appOrigin,
      walletOrigin,
      redeemedAtMs: 352,
    });
    expect(redeemed).toMatchObject({
      kind: 'redeemed',
      walletSessionId: first.session.walletSessionId,
      operationCredential: {
        kind: 'opaque_hosted_wallet_session_operation_credential_v1',
        token: expect.stringMatching(/^wsh_[A-Za-z0-9_-]{43}$/),
        walletSessionId: first.session.walletSessionId,
      },
      expiresAtMs: first.session.expiresAtMs,
    });
    if (redeemed.kind !== 'redeemed') throw new Error('hosted exchange did not redeem');
    await expect(
      service.readHostedWalletSessionOperationCredentialV2({
        tenantId,
        token: redeemed.operationCredential.token,
        requestOrigin: parseSessionOrigin('https://wrong.hosted.example.test'),
        nowMs: 353,
      }),
    ).resolves.toBeNull();
    await expect(
      service.readHostedWalletSessionOperationCredentialV2({
        tenantId,
        token: redeemed.operationCredential.token,
        requestOrigin: walletOrigin,
        nowMs: 353,
      }),
    ).resolves.toMatchObject({
      kind: 'resolved_hosted_wallet_session_operation_credential_v2',
      authorization: { session: first.session, quota: first.quota },
      appOrigin,
      walletOrigin,
    });
    await expect(
      service.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId,
        token: first.operationCredential.token,
        nowMs: 353,
      }),
    ).resolves.toEqual({ session: first.session, quota: first.quota });
    await expect(
      service.readHostedWalletSessionOperationCredentialV2({
        tenantId,
        token: first.operationCredential.token,
        requestOrigin: walletOrigin,
        nowMs: 353,
      }),
    ).resolves.toBeNull();
    await expect(
      service.readHostedWalletSessionOperationCredentialV2({
        tenantId,
        token: redeemed.operationCredential.token,
        requestOrigin: walletOrigin,
        nowMs: first.session.expiresAtMs,
      }),
    ).resolves.toBeNull();
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind
             FROM wallet_session_hosted_exchange_codes_v2
            WHERE namespace = ? AND tenant_id = ?`,
        )
        .bind(namespace, tenantId)
        .first(),
    ).resolves.toEqual({ lifecycle_kind: 'consumed' });
    await expect(
      rowCount(temporary.database, 'wallet_session_hosted_credentials_v2'),
    ).resolves.toBe(1);
    await expect(
      service.redeemHostedWalletSeamsSessionExchange({
        exchangeCode: delivery.exchangeCode,
        nonce: delivery.nonce,
        appOrigin,
        walletOrigin,
        redeemedAtMs: 354,
      }),
    ).resolves.toEqual({ kind: 'already_consumed' });

    await service.mintHostedWalletSeamsSessionExchange({
      authorization: { session: first.session, quota: first.quota },
      appOrigin,
      walletOrigin,
      issuedAtMs: 360,
      expiresAtMs: 600,
    });
    const operation = buildCapabilityOperationEnvelope({
      tenantId: first.session.tenantId,
      principalId: first.session.principalId,
      capabilityId: requiredParsed(
        parseCapabilityId(String(fixture.authority.signerActivations.ed25519.capability)),
      ),
      operationId: requiredParsed(parseCapabilityOperationId('operation:hosted-quota')),
      operation: buildNearEd25519MpcOperationRef(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction),
      digests: {
        laneDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(84))),
        intentDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(85))),
        displayDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(86))),
      },
    });
    const claimInput = await buildAuthorizedOperation({
      tenantId: first.session.tenantId,
      authorizedOperationId: requiredParsed(
        parseAuthorizedOperationId('authorized-operation:hosted-quota'),
      ),
      auditEventId: requiredParsed(parseAuthorizationAuditEventId('audit:hosted-quota')),
      operation,
      authorization: {
        kind: 'authorization_grant',
        authorizationGrantRef: buildAuthorizationGrantRef(first.session.authorizationId),
      },
      quota: {
        kind: 'consume_reusable_wallet_session',
        quotaId: first.session.quotaId,
      },
      claimedAtMs: 361,
    });
    await expect(
      service.admitAuthorizedOperation({ operation: claimInput }),
    ).resolves.toMatchObject({
      kind: 'claimed',
    });
    await expect(
      service.readHostedWalletSessionOperationCredentialV2({
        tenantId,
        token: redeemed.operationCredential.token,
        requestOrigin: walletOrigin,
        nowMs: 362,
      }),
    ).resolves.toBeNull();
    await expect(
      service.readExactWalletSessionStatusByOperationCredential({
        tenantId,
        token: first.operationCredential.token,
        nowMs: 362,
      }),
    ).resolves.toMatchObject({
      kind: 'exhausted',
      session: first.session,
      quota: { remainingUses: 0, lifecycle: 'exhausted' },
    });
    const replacement = await service.issueDirectWalletSessionAuthorizationV2({
      ...firstInput,
      mintId: requiredMintId('unlock:hosted-exchange:replacement'),
      issuedAtMs: 400,
      expiresAtMs: 650,
    });
    expect(replacement.kind).toBe('issued');
    await expect(
      temporary.database
        .prepare(
          `SELECT lifecycle_kind, retired_at_ms
             FROM wallet_session_hosted_credentials_v2
            WHERE namespace = ? AND tenant_id = ?`,
        )
        .bind(namespace, tenantId)
        .first(),
    ).resolves.toMatchObject({ lifecycle_kind: 'retired' });
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM wallet_session_hosted_exchange_codes_v2
            WHERE namespace = ? AND tenant_id = ? AND lifecycle_kind = 'issued'`,
        )
        .bind(namespace, tenantId)
        .first<{ readonly count?: unknown }>(),
    ).resolves.toEqual({ count: 0 });
    await expect(
      service.readHostedWalletSessionOperationCredentialV2({
        tenantId,
        token: redeemed.operationCredential.token,
        requestOrigin: walletOrigin,
        nowMs: 401,
      }),
    ).resolves.toBeNull();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('hosted exchange routes require the dedicated wallet-origin policy and V2 wire', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'hosted-wallet-v2-route';
    const service = createService(temporary.database, namespace);
    const fixture = await seedActiveAuthority(temporary.database, namespace, 'hosted-route');
    const tenantId = requiredParsed(parseTenantId('tenant:hosted-route'));
    const principalId = requiredParsed(parsePrincipalId('principal:hosted-route'));
    const issued = await service.issueDirectWalletSessionAuthorizationV2({
      tenantId,
      principalId,
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:hosted-route'),
      remainingUses: 2,
      issuedAtMs: 300,
      expiresAtMs: 700,
    });
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') throw new Error('hosted route parent issuance did not issue');
    const appOrigin = parseSessionOrigin('https://app.hosted-route.example.test');
    const walletOrigin = parseSessionOrigin('https://wallet.hosted-route.example.test');
    const exchangeCode = parseHostedWalletSeamsSessionExchangeCode(`hse_${'d'.repeat(43)}`);
    const nonce = parseHostedWalletSeamsSessionExchangeNonce(`hsn_${'e'.repeat(43)}`);
    const primaryToken = `wst_${'b'.repeat(43)}`;
    let readCount = 0;
    const delivery = {
      kind: 'hosted_wallet_session_exchange_delivery_v2' as const,
      exchangeCode,
      nonce,
      appOrigin,
      walletOrigin,
      expiresAtMs: 650,
    };
    const operationCredential = {
      kind: 'opaque_hosted_wallet_session_operation_credential_v1' as const,
      token: `wsh_${'c'.repeat(43)}`,
      walletSessionId: issued.session.walletSessionId,
    };
    const sessions = {
      tenantId,
      readWalletSessionAuthorizationV2ByOperationCredential: async () => {
        readCount += 1;
        return {
          authorization: { session: issued.session, quota: issued.quota },
          authority: fixture.authority,
          authMethod: fixture.authMethod,
          retiredAtMs: null,
        };
      },
      mintHostedWalletSeamsSessionExchange: async () => delivery,
      redeemHostedWalletSeamsSessionExchange: async () => ({
        kind: 'redeemed' as const,
        walletSessionId: issued.session.walletSessionId,
        operationCredential,
        expiresAtMs: 650,
      }),
    };
    const issueResponse = await handleHostedWalletSessionExchangeIssue(
      hostedRouteContext({
        pathname: '/wallet/session/exchange/issue',
        request: new Request('https://api.example.test/wallet/session/exchange/issue', {
          method: 'POST',
          headers: {
            authorization: `Bearer ${primaryToken}`,
            origin: appOrigin,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ appOrigin, walletOrigin }),
        }),
        hostedWalletOrigins: [walletOrigin],
        authorizationSessions: sessions,
      }),
    );
    expect(issueResponse?.status).toBe(200);
    await expect(issueResponse?.json()).resolves.toEqual({
      ok: true,
      delivery: {
        exchangeCode: delivery.exchangeCode,
        nonce: delivery.nonce,
        appOrigin: delivery.appOrigin,
        walletOrigin: delivery.walletOrigin,
        expiresAtMs: delivery.expiresAtMs,
      },
    });
    const corsOnlyResponse = await handleHostedWalletSessionExchangeIssue(
      hostedRouteContext({
        pathname: '/wallet/session/exchange/issue',
        request: new Request('https://api.example.test/wallet/session/exchange/issue', {
          method: 'POST',
          headers: {
            authorization: `Bearer ${primaryToken}`,
            origin: appOrigin,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ appOrigin, walletOrigin }),
        }),
        hostedWalletOrigins: [],
        authorizationSessions: sessions,
      }),
    );
    expect(corsOnlyResponse?.status).toBe(403);
    expect(readCount).toBe(1);
    const redeemResponse = await handleHostedWalletSessionExchangeRedeem(
      hostedRouteContext({
        pathname: '/wallet/session/exchange/redeem',
        request: new Request('https://api.example.test/wallet/session/exchange/redeem', {
          method: 'POST',
          headers: { origin: walletOrigin, 'content-type': 'application/json' },
          body: JSON.stringify({
            exchangeCode: delivery.exchangeCode,
            nonce: delivery.nonce,
            appOrigin,
            walletOrigin,
          }),
        }),
        hostedWalletOrigins: [walletOrigin],
        authorizationSessions: sessions,
      }),
    );
    expect(redeemResponse?.status).toBe(200);
    const redeemBody = await redeemResponse?.json();
    expect(redeemBody).toMatchObject({ ok: true, operationCredential });
    expect(redeemBody).not.toHaveProperty('walletSessionToken');
    expect(redeemBody).not.toHaveProperty('curve');
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
    const committedDigest = await digestOpaqueCredentialForTest(first.operationCredential.token);
    const concurrentReplay = await createAuthorizationStore(
      temporary.database,
      namespace,
    ).commitDirectWalletSessionAuthorizationV2({
      persisted: buildPersistedActiveWalletSessionAuthorizationV2({
        session: first.session,
        quota: first.quota,
        primaryOperationCredentialDigestB64u: committedDigest,
      }),
    });
    expect(concurrentReplay).toMatchObject({
      kind: 'already_committed',
      committed: {
        session: first.session,
        primaryOperationCredentialDigestB64u: committedDigest,
      },
    });
    await expect(
      createAuthorizationStore(temporary.database, namespace).commitDirectWalletSessionAuthorizationV2({
        persisted: buildPersistedActiveWalletSessionAuthorizationV2({
          session: first.session,
          quota: first.quota,
          primaryOperationCredentialDigestB64u: losingDigest,
        }),
      }),
    ).rejects.toThrow('different credential digest');

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
    const replacementReplay =
      await service.issueDirectWalletSessionAuthorizationV2(replacementInput);
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

test('direct V2 recovery login issues and replays the exact recovered authority session', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const namespace = 'wallet-session-v2-recovery-direct';
    const service = createService(temporary.database, namespace);
    const fixture = await buildActiveAuthorityFixture('recovery-direct');
    const authority = await recoveredAuthority(fixture.authority);
    const pendingAuthority = await pendingRecoveredAuthority(
      authority,
      fixture.pendingAuthority.localInstallPackageSetDigestB64u,
    );
    const authorityStore = new D1WalletAuthorityStore({
      database: temporary.database,
      scope: {
        namespace,
        orgId: 'test-org',
        projectId: 'test-project',
        envId: 'test-env',
      },
      ensureSchema: false,
    });
    await expect(
      authorityStore.commitPendingAuthority({
        authority: pendingAuthority,
        authMethod: fixture.pendingAuthMethod,
      }),
    ).resolves.toMatchObject({ kind: 'committed_wallet_authority_v1' });
    await expect(
      authorityStore.activatePendingAuthority({
        pendingAuthority,
        activeAuthority: authority,
        pendingAuthMethod: fixture.pendingAuthMethod,
        activeAuthMethod: fixture.authMethod,
      }),
    ).resolves.toMatchObject({ kind: 'activated' });
    const input = {
      tenantId: requiredParsed(parseTenantId('tenant:v2-recovery-direct')),
      principalId: requiredParsed(parsePrincipalId('principal:v2-recovery-direct')),
      walletId: authority.walletId,
      authority,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:v2-recovery-direct'),
      remainingUses: 3,
      issuedAtMs: 300,
      expiresAtMs: 500,
    } as const;

    const first = await service.issueDirectWalletSessionAuthorizationV2(input);
    expect(first.kind).toBe('issued');
    if (first.kind !== 'issued') throw new Error('recovered direct issuance did not issue');
    expect(first.session).toMatchObject({
      kind: 'wallet_session_authorization_v2',
      walletId: authority.walletId,
      authorityId: authority.authorityId,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      authorityDigestB64u: authority.authorityDigestB64u,
    });

    const replay = await service.issueDirectWalletSessionAuthorizationV2(input);
    expect(replay).toEqual({
      kind: 'already_committed',
      walletId: first.session.walletId,
      authorityId: first.session.authorityId,
      walletAuthMethodId: first.session.walletAuthMethodId,
      mintId: first.session.mintId,
      authorizationId: first.session.authorizationId,
      walletSessionId: first.session.walletSessionId,
      quotaId: first.session.quotaId,
      next: 'unlock_exact_method',
    });
    expect(replay).not.toHaveProperty('operationCredential');
    expect(replay).not.toHaveProperty('walletSessionToken');
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

    const claimed = await service.admitAuthorizedOperation({ operation: claimInput });
    expect(claimed.kind).toBe('claimed');
    if (claimed.kind !== 'claimed') throw new Error('V2 operation admission was not claimed');
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

    const siblingMethod = buildSiblingActivePasskeyAuthMethod(fixture.authMethod, 41);
    await prepareD1WalletAuthMethodV2PutStatement({
      database: temporary.database,
      scope: {
        namespace,
        orgId: 'test-org',
        projectId: 'test-project',
        envId: 'test-env',
      },
      record: siblingMethod,
      insertOnly: true,
    }).run();
    const siblingIssue = await service.issueDirectWalletSessionAuthorizationV2({
      tenantId: session.session.tenantId,
      principalId: session.session.principalId,
      walletId: fixture.authority.walletId,
      authority: fixture.authority,
      walletAuthMethodId: siblingMethod.walletAuthMethodId,
      mintId: requiredMintId('unlock:v2-claim-sibling'),
      remainingUses: 2,
      issuedAtMs: 303,
      expiresAtMs: 400,
    });
    if (siblingIssue.kind !== 'issued') {
      throw new Error('Sibling-method V2 operation fixture did not issue');
    }
    const siblingRetry = await buildAuthorizedOperation({
      ...retry,
      authorization: {
        kind: 'authorization_grant',
        authorizationGrantRef: buildAuthorizationGrantRef(siblingIssue.session.authorizationId),
      },
      quota: {
        kind: 'consume_reusable_wallet_session',
        quotaId: siblingIssue.session.quotaId,
      },
      claimedAtMs: 304,
    });
    await expect(
      service.admitAuthorizedOperation({ operation: siblingRetry }),
    ).resolves.toEqual({ kind: 'authorization_grant_rejected' });
    await expect(
      temporary.database
        .prepare(
          `SELECT remaining_uses
             FROM authorization_wallet_session_quotas
            WHERE namespace = ? AND tenant_id = ? AND quota_id = ?`,
        )
        .bind(namespace, siblingIssue.session.tenantId, siblingIssue.session.quotaId)
        .first(),
    ).resolves.toEqual({ remaining_uses: 2 });

    const completed = await service.completeAuthorizedOperation({
      operation: claimed.operation,
      result: 'succeeded',
      response: { status: 200, contentType: 'application/json', bodyText: '{"ok":true}' },
      completedAtMs: 305,
    });
    expect(completed.lifecycle).toBe('completed');
    await expect(
      service.admitAuthorizedOperation({ operation: { ...retry, claimedAtMs: 306 } }),
    ).resolves.toMatchObject({ kind: 'replayed' });

    const persistedScope = await temporary.database
      .prepare(
        `SELECT linked_scope_org_id, linked_scope_project_id, linked_scope_env_id
           FROM authorized_operations
          WHERE namespace = ? AND tenant_id = ? AND authorized_operation_id = ?`,
      )
      .bind(namespace, session.session.tenantId, String(claimInput.authorizedOperationId))
      .first();
    expect(persistedScope).toEqual({
      linked_scope_org_id: DEFAULT_AUTHORIZATION_SCOPE.orgId,
      linked_scope_project_id: DEFAULT_AUTHORIZATION_SCOPE.projectId,
      linked_scope_env_id: DEFAULT_AUTHORIZATION_SCOPE.envId,
    });
    for (const scope of [
      { ...DEFAULT_AUTHORIZATION_SCOPE, orgId: 'other-org' },
      { ...DEFAULT_AUTHORIZATION_SCOPE, projectId: 'other-project' },
      { ...DEFAULT_AUTHORIZATION_SCOPE, envId: 'other-env' },
    ]) {
      await expect(
        createService(temporary.database, namespace, scope).admitAuthorizedOperation({
          operation: { ...retry, claimedAtMs: 306 },
        }),
      ).resolves.toEqual({ kind: 'authorization_grant_rejected' });
    }

    await service.retireWalletSessionAuthorizationsForAuthMethod({
      tenantId: session.session.tenantId,
      walletId: session.session.walletId,
      walletAuthMethodId: session.session.walletAuthMethodId,
      nowMs: 307,
    });
    await expect(
      service.admitAuthorizedOperation({ operation: { ...retry, claimedAtMs: 308 } }),
    ).resolves.toEqual({ kind: 'authorization_grant_rejected' });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

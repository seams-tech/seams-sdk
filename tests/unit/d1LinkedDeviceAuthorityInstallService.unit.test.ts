import { expect, test } from '@playwright/test';
import {
  buildFullOwnerPermissionsV1,
  buildSigningOnlyPermissionsV1,
} from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import type {
  OrdinaryEcdsaSignerMaterialWorkerReservationV1,
  OrdinaryEcdsaSignerMaterialReservationRequestV1,
  OrdinaryInactiveSignerMaterialReservationWorkerPortV1,
} from '../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import { OrdinaryInactiveSignerMaterialReservationServiceV1 } from '../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceOwnerAuthorizationPortV1,
} from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import type {
  PasskeyWalletAuthMethodDraftV1,
} from '@shared/utils/registrationIntent';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  AuthorizationService,
  type PreparedWalletSessionAuthorizationV2,
} from '../../packages/wallet-server/src/authorization/service';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import {
  buildExactAdministeredSignerManifestV1,
  parseExactAdministeredSignerManifestV1,
} from '@shared/device-linking/delegatedActivationPlan';
import type { VerifiedLinkInputV1 } from '@shared/device-linking/contracts';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import {
  buildOrdinaryEcdsaClientMaterialFixture,
  buildOrdinaryEcdsaReservationPreparationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  D1LinkedDeviceAuthorityInstallServiceV1,
  type D1LinkedDeviceAuthorityInstallServiceOptionsV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceAuthorityInstallService';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import {
  D1WalletAuthorityStore,
  type D1WalletAuthorityStoreScope,
} from '../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseDeviceId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
} from '@shared/utils/domainIds';

const scope: D1WalletAuthorityStoreScope & D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_test',
  projectId: 'project_test',
  envId: 'env_test',
};
const nowMs = 3_000;

type HarnessOptions = {
  readonly authorizationService?: Pick<
    AuthorizationService,
    'prepareWalletSessionAuthorizationV2' | 'issueWalletSessionAuthorizationV2'
  >;
  readonly authorizationStore?: D1LinkedDeviceAuthorityInstallServiceOptionsV1['authorizationStore'];
  readonly materialActivation?: D1LinkedDeviceAuthorityInstallServiceOptionsV1['materialActivation'];
};

test('allocates one opaque authority id and replays the persisted id', async () => {
  const temporary = await openDatabase();
  try {
    const source = await buildSourceAuthority();
    const harness = await buildHarness(temporary, source, 'r103-authority-id');

    const first = await harness.install.commitPendingAuthorityV1(harness.input);
    expect(first.kind).toBe('committed');
    if (first.kind !== 'committed') throw new Error('expected first authority commit');
    const authorityId = String(first.packages.authority.authorityId);
    expect(authorityId.startsWith('wallet-authority:')).toBe(true);

    const allocation = await temporary.database
      .prepare(
        `SELECT authority_id
           FROM linked_device_authority_allocations
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        String(harness.input.linkSessionId),
      )
      .first<{ readonly authority_id?: unknown }>();
    expect(allocation?.authority_id).toBe(authorityId);

    const replay = await harness.install.commitPendingAuthorityV1(harness.input);
    expect(replay.kind).toBe('replayed');
    if (replay.kind !== 'replayed') throw new Error('expected authority replay');
    expect(String(replay.packages.authority.authorityId)).toBe(authorityId);

    const oldCanonicalDigest = base64UrlEncode(
      await sha256BytesUtf8(
        alphabetizeStringify([
          'linked-device-authority-v1',
          harness.input.walletId,
          harness.input.enrollmentId,
          harness.input.linkSessionId,
          harness.input.targetDeviceId,
          harness.input.sourceAuthority.authMethodId,
          harness.input.sourceAuthority.authority.authorityDigestB64u,
          harness.input.sourceAuthority.verifiedRevocationEpoch,
          harness.input.targetFactor.verificationDigestB64u,
          harness.input.permissions,
          harness.input.signerManifest,
        ]),
      ),
    );
    expect(authorityId).not.toBe(`wauth_link_${oldCanonicalDigest}`);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('allocates a fresh authority id when the same physical device relinks', async () => {
  const firstTemporary = await openDatabase();
  const secondTemporary = await openDatabase();
  try {
    const source = await buildSourceAuthority();
    const firstHarness = await buildHarness(firstTemporary, source, 'r103-authority-first');
    const secondHarness = await buildHarness(secondTemporary, source, 'r103-authority-second');

    const first = await firstHarness.install.commitPendingAuthorityV1(firstHarness.input);
    const second = await secondHarness.install.commitPendingAuthorityV1(secondHarness.input);
    expect(first.kind).toBe('committed');
    expect(second.kind).toBe('committed');
    if (first.kind !== 'committed' || second.kind !== 'committed') {
      throw new Error('expected both link sessions to commit');
    }
    expect(second.packages.authority.provenance.kind).toBe('device_link');
    expect(String(first.packages.authority.authorityId)).not.toBe(
      String(second.packages.authority.authorityId),
    );
    expect(first.packages.authority.principal.deviceId).toBe(
      second.packages.authority.principal.deviceId,
    );
  } finally {
    cleanupTemporaryD1Database(firstTemporary.tempDir);
    cleanupTemporaryD1Database(secondTemporary.tempDir);
  }
});

test('rolls back authority activation and converges with a prepared Wallet Session on retry', async () => {
  const temporary = await openDatabase();
  try {
    const source = await buildSourceAuthority();
    const authorizationStore = new CloudflareD1AuthorizationStore({
      database: temporary.database,
      namespace: scope.namespace,
      walletSignerScope: scope,
    });
    const authorizationService = new AuthorizationService({
      policy: capabilityPolicyPort,
      sessions: authorizationStore,
      evidence: authorizationStore,
      grants: authorizationStore,
      authorizedOperations: authorizationStore,
      audit: authorizationStore,
    });
    let failNextWalletSessionStatement = true;
    const harness = await buildHarness(temporary, source, 'r103-atomic-activation', {
      authorizationService,
      authorizationStore: {
        prepareWalletSessionAuthorizationV2Statements: (
          input: PreparedWalletSessionAuthorizationV2,
        ) => {
          const statements = authorizationStore.prepareWalletSessionAuthorizationV2Statements(input);
          if (!failNextWalletSessionStatement) return statements;
          failNextWalletSessionStatement = false;
          const [quotaStatement] = statements;
          if (!quotaStatement) throw new Error('Wallet Session quota statement is missing');
          return [
            quotaStatement,
            temporary.database.prepare('SELECT * FROM forced_atomic_activation_fault'),
          ];
        },
      },
      materialActivation: {
        activateOrdinaryInactiveSignerMaterialV1: async () => undefined,
      },
    });

    const committed = await harness.install.commitPendingAuthorityV1(harness.input);
    expect(committed.kind).toBe('committed');
    if (committed.kind !== 'committed') throw new Error('expected pending authority commit');
    const installedAtMs = nowMs + 1;
    const receipt = {
      kind: 'local_authority_installation_receipt_v1' as const,
      authorityId: committed.packages.authority.authorityId,
      walletId: committed.packages.authority.walletId,
      authMethodId: committed.packages.authMethod.walletAuthMethodId,
      deviceId: harness.input.targetDeviceId,
      packageSetDigestB64u: committed.packages.packageSetDigestB64u,
      installedActivationRefs: committed.packages.authority.signerActivations,
      installedRecordSetDigestB64u: parseDigestB64u(
        base64UrlEncode(new Uint8Array(32).fill(89)),
      ),
      targetFactorVerificationDigestB64u: harness.input.targetFactor.verificationDigestB64u,
      installedAtMs,
    };

    const failed = await harness.install.activateInstalledAuthorityV1({
      receipt,
      nowMs: installedAtMs,
    });
    expect(failed.kind).toBe('integrity_error');

    const pendingAuthority = await harness.authorityStore.readById(receipt.authorityId);
    expect(pendingAuthority?.state).toBe('pending_local_install');
    const pendingAuthMethod = await harness.authMethodStore.readByIdV2({
      walletAuthMethodId: receipt.authMethodId,
    });
    expect(pendingAuthMethod?.status).toBe('pending_local_install');
    const pendingSession = await harness.sessionStore.getSessionV1(harness.input.linkSessionId);
    expect(pendingSession?.state.state).toBe('authority_pending_local_install');
    expect(
      await readWalletSessionAuthorizationCount(
        temporary.database,
        receipt.walletId,
        receipt.authorityId,
      ),
    ).toBe(0);
    expect(await readWalletSessionQuotaCount(temporary.database)).toBe(0);

    const replay = await harness.install.activateInstalledAuthorityV1({
      receipt,
      nowMs: installedAtMs,
    });
    expect(replay.kind).toBe('active');
    if (replay.kind !== 'active') throw new Error('expected activation replay to converge');
    expect(replay.outcome).toBe('activated');
    expect(replay.authority.state).toBe('active');
    expect(replay.authMethod.status).toBe('active');
    expect(replay.session.state.state).toBe('active');
    expect(
      await readWalletSessionAuthorizationCount(
        temporary.database,
        receipt.walletId,
        receipt.authorityId,
      ),
    ).toBe(1);
    expect(await readWalletSessionQuotaCount(temporary.database)).toBe(1);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

async function openDatabase(): Promise<TemporaryD1Database> {
  const temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  return temporary;
}

async function buildHarness(
  temporary: TemporaryD1Database,
  source: SourceFixture,
  label: string,
  options: HarnessOptions = {},
): Promise<{
  readonly install: D1LinkedDeviceAuthorityInstallServiceV1;
  readonly input: VerifiedLinkInputV1 & { readonly nowMs: number };
  readonly authorityStore: D1WalletAuthorityStore;
  readonly authMethodStore: Pick<D1WalletAuthMethodStore, 'readByIdV2'>;
  readonly sessionStore: D1LinkedDeviceSessionStoreV1;
}> {
  const fixture = buildR103DeviceLinkFixture({
    linkSessionId: `link-session:${label}`,
    enrollmentId: `enrollment:${label}`,
    deviceId: 'device:r103',
  });
  const sessionStore = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store: sessionStore,
    authorization: ownerAuthorization(fixture),
  });
  await reachProvisioning(sessionService, fixture);

  const targetSigner = buildTargetSigner(String(source.authority.walletId), label);
  const targetManifest = buildExactAdministeredSignerManifestV1([targetSigner]);
  const targetActivation = buildMpcMaterialActivationRefFixture(
    `target-${label}`,
    String(source.authority.walletId),
    `worker:target-${label}`,
  );
  const targetPreparation = buildOrdinaryEcdsaReservationPreparationFixture(
    `target-${label}`,
    targetActivation,
  );
  const input: VerifiedLinkInputV1 & { readonly nowMs: number } = {
    nowMs,
    walletId: source.authority.walletId,
    linkSessionId: fixture.payload.linkSessionId,
    enrollmentId: fixture.approval.enrollmentId,
    targetDeviceId: parseDeviceId(String(fixture.approval.deviceId)).value,
    sourceAuthority: {
      authority: source.authority,
      authMethodId: source.authMethod.walletAuthMethodId,
      verifiedRevocationEpoch: source.authority.revocationEpoch,
      authorityDigestB64u: source.authority.authorityDigestB64u,
      verifiedAtMs: nowMs,
    },
    targetFactor: {
      kind: 'verified_passkey_target_v1',
      authMethod: targetPasskeyDraft(source.authority.walletId, label),
      verificationDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(49))),
      verifiedAtMs: nowMs,
    },
    permissions: buildSigningOnlyPermissionsV1(),
    signerManifest: targetManifest,
    ordinarySignerMaterialRecipientRequests: [
      {
        kind: 'ordinary_ecdsa_signer_material_recipient_request_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletKeyId: targetSigner.walletKeyId,
        clientEphemeralPublicKey: targetPreparation.registrationRequest.client_ephemeral_public_key,
      },
    ],
  };
  const authorityStore = new D1WalletAuthorityStore({ database: temporary.database, scope });
  const walletAuthMethodStore = new D1WalletAuthMethodStore({
    database: temporary.database,
    ...scope,
  });
  const authMethodStore: Pick<D1WalletAuthMethodStore, 'readByIdV2'> = {
    readByIdV2: async (input) =>
      (await walletAuthMethodStore.readByIdV2(input)) ??
      (input.walletAuthMethodId === source.authMethod.walletAuthMethodId ? source.authMethod : null),
  };
  const reservationService = new OrdinaryInactiveSignerMaterialReservationServiceV1(
    new EcdsaReservationWorkerFixture(),
  );
  const serviceOptions: D1LinkedDeviceAuthorityInstallServiceOptionsV1 = {
    database: temporary.database,
    scope,
    authorityStore,
    authMethodStore,
    sessionStore,
    sessionService: {
      getSessionV1: async ({ linkSessionId, nowMs: requestedAtMs }) =>
        await sessionService.getSessionV1({ linkSessionId, nowMs: requestedAtMs }),
      deleteActiveSessionV1: async () => {
        throw new Error('active-session deletion is outside this commit test');
      },
    },
    reservationService,
    materialActivation: options.materialActivation ?? {
      activateOrdinaryInactiveSignerMaterialV1: async () => {
        throw new Error('activation is outside this commit test');
      },
    },
    authorizationService: options.authorizationService ?? {
      prepareWalletSessionAuthorizationV2: unsupportedAuthorizationOperation,
      issueWalletSessionAuthorizationV2: unsupportedAuthorizationOperation,
    },
    authorizationStore: options.authorizationStore ?? {
      prepareWalletSessionAuthorizationV2Statements: unsupportedAuthorizationStatements,
    },
    tenantId: 'tenant:r103',
  };
  return {
    install: new D1LinkedDeviceAuthorityInstallServiceV1(serviceOptions),
    input,
    authorityStore,
    authMethodStore,
    sessionStore,
  };
}

async function readWalletSessionAuthorizationCount(
  database: TemporaryD1Database['database'],
  walletId: SourceFixture['authority']['walletId'],
  authorityId: SourceFixture['authority']['authorityId'],
): Promise<number> {
  const row = await database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM wallet_session_authorizations_v2
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND tenant_id = ? AND wallet_id = ? AND authority_id = ?`,
    )
    .bind(
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      'tenant:r103',
      String(walletId),
      String(authorityId),
    )
    .first<{ readonly count?: unknown }>();
  return Number(row?.count ?? 0);
}

async function readWalletSessionQuotaCount(
  database: TemporaryD1Database['database'],
): Promise<number> {
  const row = await database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM authorization_wallet_session_quotas
        WHERE namespace = ? AND tenant_id = ?`,
    )
    .bind(scope.namespace, 'tenant:r103')
    .first<{ readonly count?: unknown }>();
  return Number(row?.count ?? 0);
}

type SourceFixture = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ReturnType<typeof buildWalletAuthMethodRecordV2>;
};

async function buildSourceAuthority(): Promise<SourceFixture> {
  const walletId = parseWalletId('wallet:r103').value;
  const sourceSigner = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: 'wallet-key:r103-source',
        thresholdPublicKey33B64u: base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(7)])),
        evmAddress: '0x1111111111111111111111111111111111111111',
      },
    ],
  });
  const sourceActivation = buildMpcMaterialActivationRefFixture(
    'source-r103',
    String(walletId),
    'worker:source-r103',
  );
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: sourceSigner,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: sourceActivation,
    },
  });
  const signerActivationSetDigestB64u = await computeWalletSignerActivationSetDigestB64u(
    signerActivations,
  );
  const authorityId = parseWalletAuthorityId('authority:r103-source').value;
  const authorityDraft = {
    kind: 'wallet_authority_v1' as const,
    authorityId,
    walletId,
    principal: { kind: 'owner_device' as const, deviceId: parseDeviceId('device:r103-source').value },
    provenance: { kind: 'wallet_registration' as const },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(61))),
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
    state: 'active' as const,
    activatedAtMs: 100,
  };
  const authority = buildActiveWalletAuthorityV1({
    ...authorityDraft,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityDraft),
  });
  const rpId = parseWebAuthnRpId('r103.example.test').value;
  const credentialIdB64u = parseWebAuthnCredentialIdB64u(
    base64UrlEncode(new Uint8Array(32).fill(63)),
  ).value;
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: parseWalletAuthMethodId('wallet-auth-method:r103-source').value,
    walletId,
    walletAuthorityId: authority.authorityId,
    kind: 'passkey',
    status: 'active',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(67)),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 100,
    activatedAtMs: 100,
  });
  return { authority, authMethod };
}

function buildTargetSigner(walletId: string, label: string) {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: `wallet-key:r103-target-${label}`,
        thresholdPublicKey33B64u: base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(11)])),
        evmAddress: '0x2222222222222222222222222222222222222222',
      },
    ],
  });
  const signer = manifest.signers[0];
  if (signer?.keyFamily !== 'ecdsa_secp256k1') throw new Error('target signer fixture is invalid');
  return signer;
}

function targetPasskeyDraft(walletId: ActiveWalletAuthorityV1['walletId'], label: string): PasskeyWalletAuthMethodDraftV1 {
  return {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: parseWalletAuthMethodId(`wallet-auth-method:r103-target-${label}`).value,
    walletId,
    walletAuthorityId: parseWalletAuthorityId(`authority:r103-target-draft-${label}`).value,
    kind: 'passkey',
    rpId: parseWebAuthnRpId('r103.example.test').value,
    credentialIdB64u: parseWebAuthnCredentialIdB64u(
      base64UrlEncode(new Uint8Array(32).fill(71)),
    ).value,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(73)),
    counter: 0,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

function ownerAuthorization(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async () => ({
      kind: 'authorized' as const,
      identity: {
        walletId: fixture.approval.walletId,
        enrollmentId: fixture.approval.enrollmentId,
        deviceId: fixture.approval.deviceId,
        claimExpiresAtMs: nowMs + 7_000,
      },
    }),
    authorizeOwnerApprovalV1: async () => ({
      kind: 'authorized' as const,
      sourceKeyManifestDigestsB64u: { ed25519: fixture.packageSetDigestB64u },
    }),
  };
}

async function reachProvisioning(
  service: LinkedDeviceSessionServiceV1,
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): Promise<void> {
  await service.createUnclaimedSessionV1({ payload: fixture.payload, nowMs });
  await service.claimSessionV1({
    payload: fixture.payload,
    owner: {
      walletId: fixture.approval.walletId,
      walletSessionId: 'wallet-session:r103-test',
      authorizationId: 'authorization:r103-test',
      expiresAtMs: nowMs + 7_000,
      permission: { kind: 'delegated_wallet_authority_v1', permissions: buildFullOwnerPermissionsV1() },
      curve: 'ecdsa',
      keyManifestDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(79))),
    },
    nowMs: nowMs + 1,
  });
  const approval = { ...fixture.approval, expiresAtMs: nowMs + 5_000 };
  const approved = await service.recordOwnerApprovalV1({
    owner: {
      walletId: approval.walletId,
      walletSessionId: 'wallet-session:r103-test',
      authorizationId: 'authorization:r103-test',
      expiresAtMs: approval.expiresAtMs,
      permission: { kind: 'delegated_wallet_authority_v1', permissions: buildFullOwnerPermissionsV1() },
      curve: 'ecdsa',
      keyManifestDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(79))),
    },
    approval,
    nowMs: nowMs + 2,
  });
  if (approved.outcome !== 'applied') throw new Error('expected approved linked-device session');
  const provisioning = await service.recordTargetCredentialV1({
    linkSessionId: fixture.payload.linkSessionId,
    expectedRevision: approved.record.revision,
    nowMs: nowMs + 3,
  });
  if (provisioning.outcome !== 'applied') throw new Error('expected provisioning linked-device session');
}

class EcdsaReservationWorkerFixture implements OrdinaryInactiveSignerMaterialReservationWorkerPortV1 {
  async reserveInactiveEd25519SignerMaterialV1(): Promise<never> {
    throw new Error('Ed25519 is outside this fixture');
  }

  async reserveInactiveEcdsaSignerMaterialV1(
    request: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialWorkerReservationV1> {
    return {
      kind: 'ordinary_ecdsa_signer_material_worker_reservation_v1',
      keyFamily: 'ecdsa_secp256k1',
      state: 'inactive',
      signer: request.signer,
      materialActivation: request.plannedActivationRef,
      clientMaterial: buildOrdinaryEcdsaClientMaterialFixture(
        'authority-install',
        request.preparation.registrationRequest.client_ephemeral_public_key,
        request.preparation.registrationRequest.signer_set.signer_a.key_epoch,
      ),
      serverMaterialReservationId: 'server-reservation:authority-install',
    };
  }
}

function unsupportedAuthorizationOperation(): Promise<never> {
  return Promise.reject(new Error('wallet-session issuance is outside this commit test'));
}

function unsupportedAuthorizationStatements(): readonly [never, never] {
  throw new Error('wallet-session statements are outside this commit test');
}

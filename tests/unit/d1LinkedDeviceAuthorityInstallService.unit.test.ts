import { expect, test } from '@playwright/test';
import {
  buildFullOwnerPermissionsV1,
  buildSigningOnlyPermissionsV1,
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
  parseOrdinaryEcdsaSignerMaterialWorkerReservationV1,
  OrdinaryInactiveSignerMaterialReservationServiceV1,
} from '../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import type {
  OrdinaryEcdsaSignerMaterialWorkerReservationV1,
  OrdinaryEcdsaSignerMaterialReservationRequestV1,
  OrdinaryInactiveSignerMaterialReservationWorkerPortV1,
} from '../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  LinkedDeviceSessionServiceV1,
  type LinkedDeviceOwnerAuthorizationPortV1,
} from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import type { PasskeyWalletAuthMethodDraftV1 } from '@shared/utils/registrationIntent';
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
import {
  buildR103DeviceLinkFixture,
  buildR103EcdsaSourceContributionPreparationV1,
  buildR103EcdsaSourceContributionV1,
  buildR103OwnerApprovalContextV1,
} from './helpers/deviceLinkContracts.fixtures';
import {
  computeCommittedSignerPackageSetDigestB64u,
  parseCommittedAuthorityPackagesV1,
  parseCommittedSignerPackageSetV1,
} from '@shared/device-linking/committedSignerPackages';
import { buildLinkedDeviceApprovalV1 } from '@shared/device-linking/parsers';
import { buildSourcePreservingEd25519ReservationRequestFixture } from './helpers/ordinarySourcePreservingReservation.fixtures';
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
import { CloudflareD1WebAuthnStore } from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { requireRouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import { parseWebAuthnCredentialIdB64u, parseWebAuthnRpId } from '@shared/utils/domainIds';
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
  readonly deviceId?: string;
  readonly authorizationService?: Pick<
    AuthorizationService,
    | 'prepareWalletSessionAuthorizationV2'
    | 'issueWalletSessionAuthorizationV2'
    | 'issueWalletSessionAuthorizationV2OperationCredential'
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
    expect(first.kind, first.kind === 'invalid_input' ? first.message : undefined).toBe(
      'committed',
    );
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
    expect(replay.kind, replay.kind === 'invalid_input' ? replay.message : undefined).toBe(
      'replayed',
    );
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
    expect(first.kind, first.kind === 'invalid_input' ? first.message : undefined).toBe(
      'committed',
    );
    expect(second.kind, second.kind === 'invalid_input' ? second.message : undefined).toBe(
      'committed',
    );
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

test('rolls back authority activation, converges on retry, and accepts the final acknowledgement', async () => {
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
          const statements =
            authorizationStore.prepareWalletSessionAuthorizationV2Statements(input);
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
    expect(committed.kind, committed.kind === 'invalid_input' ? committed.message : undefined).toBe(
      'committed',
    );
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
      installedRecordSetDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(89))),
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
    expect(replay.kind, replay.kind === 'integrity_error' ? replay.message : undefined).toBe(
      'active',
    );
    if (replay.kind !== 'active') throw new Error('expected activation replay to converge');
    expect(replay.outcome).toBe('activated');
    expect(replay.authority.state).toBe('active');
    expect(replay.authMethod.status).toBe('active');
    expect(replay.session.state.state).toBe('active');
    expect(replay.session.packageSetDigestB64u).toBe(committed.packages.packageSetDigestB64u);
    expect(
      await readWalletSessionAuthorizationCount(
        temporary.database,
        receipt.walletId,
        receipt.authorityId,
      ),
    ).toBe(1);
    expect(await readWalletSessionQuotaCount(temporary.database)).toBe(1);
    if (replay.authMethod.kind !== 'passkey') {
      throw new Error('expected linked-device activation fixture to use a passkey');
    }
    const binding = await harness.webAuthnStore.readBindingByCredential({
      rpId: String(replay.authMethod.rpId),
      credentialIdB64u: String(replay.authMethod.credentialIdB64u),
    });
    expect(binding).toMatchObject({
      version: 'webauthn_credential_binding_v1',
      rpId: String(replay.authMethod.rpId),
      credentialIdB64u: String(replay.authMethod.credentialIdB64u),
      userId: String(replay.authMethod.walletId),
    });
    expect(binding).not.toHaveProperty('nearAccountId');
    const authenticator = await temporary.database
      .prepare(
        `SELECT credential_public_key_b64u, counter, device_info_json
           FROM webauthn_authenticators
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
            AND credential_id_b64u = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        String(receipt.walletId),
        String(replay.authMethod.credentialIdB64u),
      )
      .first<{
        readonly credential_public_key_b64u?: unknown;
        readonly counter?: unknown;
        readonly device_info_json?: unknown;
      }>();
    expect(authenticator).toMatchObject({
      credential_public_key_b64u: replay.authMethod.credentialPublicKeyB64u,
      counter: replay.authMethod.counter,
    });
    expect(authenticator?.device_info_json).toBeTruthy();
    await harness.install.acknowledgeLocalAuthorityActivationV1({
      acknowledgement: {
        kind: 'local_authority_activation_final_ack_v1',
        linkSessionId: harness.input.linkSessionId,
        authorityId: replay.authority.authorityId,
        packageSetDigestB64u: committed.packages.packageSetDigestB64u,
        authorizationId: replay.walletSession.session.authorizationId,
        acknowledgedAtMs: installedAtMs,
      },
      session: replay.session,
      requestedAtMs: installedAtMs,
    });
    await expect(
      harness.sessionStore.getSessionV1(harness.input.linkSessionId),
    ).resolves.toBeNull();
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
      .first();
    expect(allocation).toBeNull();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('reads installed Ed25519 authority projections by identity and material activation', async () => {
  const temporary = await openDatabase();
  try {
    const source = await buildSourceAuthority();
    const harness = await buildHarness(temporary, source, 'r103');
    const committed = await harness.install.commitPendingAuthorityV1(harness.input);
    expect(committed.kind).toBe('committed');
    if (committed.kind !== 'committed') throw new Error('expected pending authority commit');
    const edRequest = buildSourcePreservingEd25519ReservationRequestFixture('r103-ed25519');
    const installed = await installCombinedEd25519ProjectionRow(
      temporary,
      harness,
      committed.packages,
      edRequest,
    );

    const byIdentity = await harness.install.readInstalledEd25519AuthorityByIdentityV1({
      walletId: harness.input.walletId,
      authorityId: committed.packages.authority.authorityId,
      walletAuthMethodId: committed.packages.authMethod.walletAuthMethodId,
    });
    expect(byIdentity).toMatchObject({
      walletId: harness.input.walletId,
      authorityId: committed.packages.authority.authorityId,
      walletAuthMethodId: committed.packages.authMethod.walletAuthMethodId,
      targetSessionId: edRequest.preparation.targetBinding.lifecycle.session_id,
      participantIds: [1, 2],
      activatedAtMs: installed.activatedAtMs,
      installedRecordSetDigestB64u: installed.installedRecordSetDigestB64u,
    });
    expect(byIdentity?.materialActivation.activationId).toBe(
      edRequest.plannedActivationRef.activationId,
    );
    expect(byIdentity?.targetBinding.session_id).toEqual(
      edRequest.preparation.targetBinding.session_id,
    );

    const byMaterial = await harness.install.readInstalledEd25519AuthorityByMaterialActivationV1({
      walletId: harness.input.walletId,
      materialActivation: edRequest.plannedActivationRef,
    });
    expect(byMaterial?.authorityId).toBe(committed.packages.authority.authorityId);
    expect(byMaterial?.walletAuthMethodId).toBe(committed.packages.authMethod.walletAuthMethodId);
    expect(
      await harness.install.readInstalledEd25519AuthorityByIdentityV1({
        walletId: harness.input.walletId,
        authorityId: committed.packages.authority.authorityId,
        walletAuthMethodId: parseWalletAuthMethodId('wallet-auth-method:missing').value,
      }),
    ).toBeNull();

    const ecdsaByIdentity = await harness.install.readInstalledEcdsaAuthorityByIdentityV1({
      walletId: harness.input.walletId,
      authorityId: committed.packages.authority.authorityId,
      walletAuthMethodId: committed.packages.authMethod.walletAuthMethodId,
    });
    expect(ecdsaByIdentity).toMatchObject({
      walletId: harness.input.walletId,
      authorityId: committed.packages.authority.authorityId,
      walletAuthMethodId: committed.packages.authMethod.walletAuthMethodId,
      deviceId: harness.input.targetDeviceId,
      activatedAtMs: installed.activatedAtMs,
    });
    expect(ecdsaByIdentity?.materialActivation).toEqual(
      committed.packages.signerPackages.ecdsa?.materialActivation,
    );
    expect(ecdsaByIdentity?.activationReceipt.binding.target.targetDeviceId).toBe(
      harness.input.targetDeviceId,
    );
    const ecdsaByMaterial = await harness.install.readInstalledEcdsaAuthorityByMaterialActivationV1(
      {
        walletId: harness.input.walletId,
        materialActivation: committed.packages.signerPackages.ecdsa!.materialActivation,
      },
    );
    expect(ecdsaByMaterial?.authorityId).toBe(committed.packages.authority.authorityId);
    expect(ecdsaByMaterial?.walletAuthMethodId).toBe(
      committed.packages.authMethod.walletAuthMethodId,
    );

    await setInstallationMarkers(temporary, harness.input.linkSessionId, null, null);
    await expect(
      harness.install.readInstalledEd25519AuthorityByIdentityV1({
        walletId: harness.input.walletId,
        authorityId: committed.packages.authority.authorityId,
        walletAuthMethodId: committed.packages.authMethod.walletAuthMethodId,
      }),
    ).resolves.toBeNull();
    await setInstallationMarkers(
      temporary,
      harness.input.linkSessionId,
      installed.installedRecordSetDigestB64u,
      installed.activatedAtMs,
    );

    const ambiguousHarness = await buildHarness(temporary, source, 'r103-ambiguous', {
      deviceId: 'device:r103-ambiguous',
    });
    const ambiguousCommitted = await ambiguousHarness.install.commitPendingAuthorityV1(
      ambiguousHarness.input,
    );
    expect(
      ambiguousCommitted.kind,
      ambiguousCommitted.kind === 'invalid_input' ? ambiguousCommitted.message : undefined,
    ).toBe('committed');
    if (ambiguousCommitted.kind !== 'committed') {
      throw new Error('expected ambiguous pending authority commit');
    }
    await installCombinedEd25519ProjectionRow(
      temporary,
      ambiguousHarness,
      ambiguousCommitted.packages,
      edRequest,
    );
    await expect(
      harness.install.readInstalledEd25519AuthorityByMaterialActivationV1({
        walletId: harness.input.walletId,
        materialActivation: edRequest.plannedActivationRef,
      }),
    ).resolves.toBeNull();
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
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
}> {
  const fixture = buildR103DeviceLinkFixture({
    linkSessionId: `link-session:${label}`,
    enrollmentId: `enrollment:${label}`,
    deviceId: options.deviceId ?? 'device:r103',
  });
  const sessionStore = new D1LinkedDeviceSessionStoreV1({ database: temporary.database, scope });
  const sessionService = new LinkedDeviceSessionServiceV1({
    store: sessionStore,
    authorization: ownerAuthorization(fixture),
  });
  await reachProvisioning(sessionService, fixture);

  const sourceContribution = buildR103EcdsaSourceContributionV1(fixture);
  if (sourceContribution.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('R103 source contribution fixture has the wrong family');
  }
  const sourceContributionPreparation = buildR103EcdsaSourceContributionPreparationV1(fixture);
  const ecdsaPreparation = sourceContributionPreparation[0];
  if (!ecdsaPreparation || 'kind' in ecdsaPreparation) {
    throw new Error('R103 ECDSA source contribution preparation is missing');
  }
  const targetSigner = buildTargetSigner(String(source.authority.walletId), sourceContribution);
  const targetManifest = buildExactAdministeredSignerManifestV1([targetSigner]);
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
      verificationDigestB64u: sourceContribution.targetFactorVerificationDigestB64u,
      verifiedAtMs: nowMs,
    },
    permissions: buildSigningOnlyPermissionsV1(),
    signerManifest: targetManifest,
    emailOtpEnrollment: null,
    ed25519ExportRootPackage: null,
    sourceContribution: [sourceContribution],
    ordinarySignerMaterialRecipientRequests: [
      {
        kind: 'ordinary_ecdsa_signer_material_recipient_request_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletKeyId: targetSigner.walletKeyId,
        clientEphemeralPublicKey: x25519PublicKeyFromB64u(
          ecdsaPreparation.target.clientRecipientPublicKeyB64u,
        ),
      },
    ],
  };
  const authorityStore = new D1WalletAuthorityStore({ database: temporary.database, scope });
  const walletAuthMethodStore = new D1WalletAuthMethodStore({
    database: temporary.database,
    ...scope,
  });
  const webAuthnStore = new CloudflareD1WebAuthnStore({
    database: temporary.database,
    ...scope,
  });
  const authMethodStore: Pick<D1WalletAuthMethodStore, 'readByIdV2'> = {
    readByIdV2: async (input) =>
      (await walletAuthMethodStore.readByIdV2(input)) ??
      (input.walletAuthMethodId === source.authMethod.walletAuthMethodId
        ? source.authMethod
        : null),
  };
  const reservationService = new OrdinaryInactiveSignerMaterialReservationServiceV1(
    new EcdsaReservationWorkerFixture(),
  );
  const serviceOptions: D1LinkedDeviceAuthorityInstallServiceOptionsV1 = {
    database: temporary.database,
    scope,
    authorityStore,
    authMethodStore,
    listWalletEd25519Signers: async () => [],
    sessionStore,
    sessionService: {
      getSessionV1: async ({ linkSessionId, nowMs: requestedAtMs }) =>
        await sessionService.getSessionV1({ linkSessionId, nowMs: requestedAtMs }),
      deleteActiveSessionV1: sessionService.deleteActiveSessionV1.bind(sessionService),
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
      issueWalletSessionAuthorizationV2OperationCredential: unsupportedAuthorizationOperation,
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
    webAuthnStore,
  };
}

async function installCombinedEd25519ProjectionRow(
  temporary: TemporaryD1Database,
  harness: Awaited<ReturnType<typeof buildHarness>>,
  basePackages: ReturnType<typeof parseCommittedAuthorityPackagesV1>,
  edRequest: ReturnType<typeof buildSourcePreservingEd25519ReservationRequestFixture>,
): Promise<{
  readonly installedRecordSetDigestB64u: DigestB64u;
  readonly activatedAtMs: number;
}> {
  if (
    basePackages.authority.signerActivations.keyFamilies.length !== 1 ||
    basePackages.authority.signerActivations.keyFamilies[0] !== 'ecdsa_secp256k1' ||
    basePackages.signerPackages.keyFamilies.length !== 1 ||
    basePackages.signerPackages.keyFamilies[0] !== 'ecdsa_secp256k1' ||
    !basePackages.authority.signerActivations.ecdsa ||
    !basePackages.signerPackages.ecdsa
  ) {
    throw new Error('projection fixture requires an ECDSA base package');
  }
  const edSource = edRequest.preparation.sourceContribution;
  const edManifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        ...edRequest.signer,
        walletId: harness.input.walletId,
        walletKeyId: 'wallet-key:r103-ed25519',
        registeredPublicKeyB64u: edSource.sourceRegisteredPublicKeyB64u,
      },
    ],
  });
  const edSigner = edManifest.signers[0];
  if (!edSigner || edSigner.keyFamily !== 'ed25519') {
    throw new Error('projection Ed25519 signer fixture is invalid');
  }
  const combinedManifest = buildExactAdministeredSignerManifestV1([
    edSigner,
    basePackages.authority.signerActivations.ecdsa.signer,
  ]);
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: combinedManifest,
    materialActivations: {
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      ed25519: edRequest.plannedActivationRef,
      ecdsa: basePackages.authority.signerActivations.ecdsa.materialActivation,
    },
  });
  const edPackages = parseCommittedSignerPackageSetV1({
    kind: 'committed_signer_package_set_v1',
    keyFamilies: ['ed25519'],
    ed25519: {
      kind: 'committed_ed25519_signer_package_v1',
      materialActivation: edRequest.plannedActivationRef,
      targetBinding: edRequest.preparation.targetBinding,
      applicationBinding: {
        ...edRequest.preparation.applicationBinding,
        wallet_id: String(harness.input.walletId),
      },
      participantIds: edSource.participantIds,
      activationReceipt: edSource.activationReceipt,
      deriver_a_client_package: edSource.deriver_a_client_package,
      deriver_b_client_package: edSource.deriver_b_client_package,
    },
  });
  if (!edPackages.ed25519) throw new Error('projection Ed25519 package is missing');
  const signerPackages = parseCommittedSignerPackageSetV1({
    kind: 'committed_signer_package_set_v1',
    keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
    ed25519: edPackages.ed25519,
    ecdsa: basePackages.signerPackages.ecdsa,
  });
  const sourceManifestDigestB64u = parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(combinedManifest))),
  );
  if (basePackages.authority.provenance.kind !== 'device_link') {
    throw new Error('projection fixture authority provenance is invalid');
  }
  const packageSetDigestB64u = await computeCommittedSignerPackageSetDigestB64u({
    authorityId: basePackages.authority.authorityId,
    walletId: basePackages.authority.walletId,
    enrollmentId: basePackages.authority.provenance.enrollmentId,
    linkSessionId: basePackages.authority.provenance.linkSessionId,
    deviceId: basePackages.authority.principal.deviceId,
    authMethodId: basePackages.authMethod.walletAuthMethodId,
    permissions: basePackages.authority.permissions,
    sourceManifestDigestB64u,
    signerPackages,
    ed25519ExportRootPackageDigestB64u: null,
    targetFactorVerificationDigestB64u: harness.input.targetFactor.verificationDigestB64u,
  });
  const authorityWithoutDigest: PendingWalletAuthorityV1 = {
    ...basePackages.authority,
    signerActivations,
    signerActivationSetDigestB64u:
      await computeWalletSignerActivationSetDigestB64u(signerActivations),
    authorityDigestB64u: packageSetDigestB64u,
    localInstallPackageSetDigestB64u: packageSetDigestB64u,
  };
  const authority = buildPendingWalletAuthorityV1({
    ...authorityWithoutDigest,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityWithoutDigest),
  });
  const packages = parseCommittedAuthorityPackagesV1({
    kind: 'committed_authority_packages_v1',
    authority,
    authMethod: basePackages.authMethod,
    signerPackages,
    ed25519ExportRootPackage: null,
    packageSetDigestB64u,
  });
  const installedRecordSetDigestB64u = parseDigestB64u(
    base64UrlEncode(new Uint8Array(32).fill(91)),
  );
  const activatedAtMs = nowMs + 1;
  await temporary.database
    .prepare(
      `UPDATE linked_device_authority_installations
          SET package_set_digest_b64u = ?, source_manifest_digest_b64u = ?, packages_json = ?,
              installed_record_set_digest_b64u = ?, activated_at_ms = ?, updated_at_ms = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      String(packageSetDigestB64u),
      String(sourceManifestDigestB64u),
      JSON.stringify(packages),
      String(installedRecordSetDigestB64u),
      activatedAtMs,
      activatedAtMs,
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(harness.input.linkSessionId),
    )
    .run();
  return { installedRecordSetDigestB64u, activatedAtMs };
}

async function setInstallationMarkers(
  temporary: TemporaryD1Database,
  linkSessionId: VerifiedLinkInputV1['linkSessionId'],
  installedRecordSetDigestB64u: DigestB64u | null,
  activatedAtMs: number | null,
): Promise<void> {
  await temporary.database
    .prepare(
      `UPDATE linked_device_authority_installations
          SET installed_record_set_digest_b64u = ?, activated_at_ms = ?, updated_at_ms = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ?`,
    )
    .bind(
      installedRecordSetDigestB64u === null ? null : String(installedRecordSetDigestB64u),
      activatedAtMs,
      nowMs + 2,
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(linkSessionId),
    )
    .run();
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
  const sourceContribution = buildR103EcdsaSourceContributionV1(buildR103DeviceLinkFixture());
  if (sourceContribution.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('R103 source contribution fixture has the wrong family');
  }
  const sourceSigner = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: sourceContribution.walletKeyId,
        thresholdPublicKey33B64u: sourceContribution.sourceSigner.thresholdPublicKey33B64u,
        evmAddress: '0x0505050505050505050505050505050505050505',
      },
    ],
  });
  const sourceActivation = sourceContribution.sourceSigner.activation;
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: sourceSigner,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: sourceActivation,
    },
  });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const authorityId = sourceContribution.sourceAuthorityId;
  const authorityDraft = {
    kind: 'wallet_authority_v1' as const,
    authorityId,
    walletId,
    principal: {
      kind: 'owner_device' as const,
      deviceId: parseDeviceId('device:r103-source').value,
    },
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

function buildTargetSigner(
  walletId: string,
  sourceContribution: Extract<
    ReturnType<typeof buildR103EcdsaSourceContributionV1>,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >,
) {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: sourceContribution.walletKeyId,
        thresholdPublicKey33B64u: sourceContribution.sourceSigner.thresholdPublicKey33B64u,
        evmAddress: '0x0505050505050505050505050505050505050505',
      },
    ],
  });
  const signer = manifest.signers[0];
  if (signer?.keyFamily !== 'ecdsa_secp256k1') throw new Error('target signer fixture is invalid');
  return signer;
}

function x25519PublicKeyFromB64u(value: string): string {
  return `x25519:${Array.from(base64UrlDecode(value), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')}`;
}

function targetPasskeyDraft(
  walletId: ActiveWalletAuthorityV1['walletId'],
  label: string,
): PasskeyWalletAuthMethodDraftV1 {
  const credentialSeed = 71 + label.length;
  return {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: parseWalletAuthMethodId(`wallet-auth-method:r103-target-${label}`).value,
    walletId,
    walletAuthorityId: parseWalletAuthorityId(`authority:r103-target-draft-${label}`).value,
    kind: 'passkey',
    rpId: parseWebAuthnRpId('r103.example.test').value,
    credentialIdB64u: parseWebAuthnCredentialIdB64u(
      base64UrlEncode(new Uint8Array(32).fill(credentialSeed)),
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
      sourceSignerManifest: fixture.sourceSignerManifest,
      sourceKeyManifestDigestsB64u: { ed25519: fixture.packageSetDigestB64u },
      sourceAuthorityDigestB64u: fixture.sourceAuthorityDigestB64u,
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
      permission: {
        kind: 'delegated_wallet_authority_v1',
        permissions: buildFullOwnerPermissionsV1(),
      },
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
      permission: {
        kind: 'delegated_wallet_authority_v1',
        permissions: buildFullOwnerPermissionsV1(),
      },
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
    sourceContributionPreparation: buildR103EcdsaSourceContributionPreparationV1(fixture),
    nowMs: nowMs + 3,
  });
  if (provisioning.outcome !== 'applied') {
    throw new Error('expected source contribution linked-device session');
  }
  const sourceContributionApproval = buildLinkedDeviceApprovalV1({
    ...approval,
    sourceContribution: [buildR103EcdsaSourceContributionV1(fixture)],
  });
  const contributed = await service.recordSourceContributionV1({
    approval: sourceContributionApproval,
    owner: buildR103OwnerApprovalContextV1(sourceContributionApproval),
    nowMs: nowMs + 4,
  });
  if (contributed.outcome !== 'applied') {
    throw new Error('expected provisioning linked-device session');
  }
}

class EcdsaReservationWorkerFixture implements OrdinaryInactiveSignerMaterialReservationWorkerPortV1 {
  async reserveInactiveEd25519SignerMaterialV1(): Promise<never> {
    throw new Error('Ed25519 is outside this fixture');
  }

  async reserveInactiveEcdsaSignerMaterialV1(
    request: OrdinaryEcdsaSignerMaterialReservationRequestV1,
  ): Promise<OrdinaryEcdsaSignerMaterialWorkerReservationV1> {
    const sourceNormalSigning = request.preparation.sourceDerivation.sourceNormalSigning;
    const sourceScope = sourceNormalSigning.scope;
    const binding = request.preparation.sourceContribution.binding;
    const targetNormalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
      kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
      scope: {
        wallet_id: sourceScope.wallet_id,
        ecdsa_threshold_key_id: sourceScope.ecdsa_threshold_key_id,
        signing_root_id: sourceScope.signing_root_id,
        signing_root_version: sourceScope.signing_root_version,
        context: sourceScope.context,
        public_identity: {
          ...sourceScope.public_identity,
          derivation_client_share_public_key33_b64u: binding.targetClientPublicKey33B64u,
          server_public_key33_b64u: binding.source.relayerPublicKey33B64u,
        },
        material_activation: routerAbMpcMaterialActivationRefToWire(binding.target.activation),
        signing_worker: {
          server_id: binding.target.activation.signingWorker,
          key_epoch: sourceScope.signing_worker.key_epoch,
          recipient_encryption_key: x25519PublicKeyFromB64u(
            binding.target.signingWorkerRecipientPublicKeyB64u,
          ),
        },
        activation_epoch: sourceScope.activation_epoch,
      },
    });
    return parseOrdinaryEcdsaSignerMaterialWorkerReservationV1(request, {
      kind: 'ordinary_ecdsa_signer_material_worker_reservation_v1',
      keyFamily: 'ecdsa_secp256k1',
      state: 'inactive',
      signer: request.signer,
      materialActivation: request.plannedActivationRef,
      activationReceipt: {
        state: 'inactive',
        binding,
        sourceDerivation: request.preparation.sourceDerivation,
        targetRelayerPublicKey33B64u: binding.source.relayerPublicKey33B64u,
        thresholdPublicKey33B64u: request.signer.thresholdPublicKey33B64u,
        thresholdEthereumAddress20B64u: binding.source.thresholdEthereumAddress20B64u,
        normalSigning: targetNormalSigning,
      },
      clientMaterial: {
        kind: 'ordinary_ecdsa_client_material_v1',
        encryptedTargetClientShare:
          request.preparation.sourceContribution.encryptedTargetClientShare,
      },
      serverMaterial: {
        kind: 'ordinary_ecdsa_inactive_server_material_v1',
        reservationId: 'server-reservation:authority-install',
        encryptedTargetServerShare: request.preparation.sourceContribution.encryptedDelta,
      },
    });
  }
}

function unsupportedAuthorizationOperation(): Promise<never> {
  return Promise.reject(new Error('wallet-session issuance is outside this commit test'));
}

function unsupportedAuthorizationStatements(): readonly [never, never] {
  throw new Error('wallet-session statements are outside this commit test');
}

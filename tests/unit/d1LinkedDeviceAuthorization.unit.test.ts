import { expect, test } from '@playwright/test';
import {
  AuthorizationService,
  deriveLinkedDeviceWalletSessionIdentityV1,
} from '../../packages/sdk-server-ts/src/authorization/service';
import { D1LinkedDeviceWalletSessionIssuerV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceWalletSessionIssuer';
import { parseLinkedDeviceSessionRecordV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import { CloudflareD1AuthorizationStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { CloudflareD1LaneEnrollmentGateway } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/d1LaneEnrollmentGateway';
import { CloudflareD1LaneLifecycleStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/d1LaneLifecycleStore';
import { capabilityPolicyPort } from '../../packages/sdk-server-ts/src/authorization/capabilityPolicy';
import { buildLinkedDevicePrincipalId } from '../../packages/sdk-server-ts/src/authorization/domain';
import {
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseTenantId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildCapabilityOperationEnvelope } from '../../packages/shared-ts/src/authorization/operationFingerprint';
import { buildNearEd25519MpcOperationRef } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import {
  computeLaneEnrollmentManifestDigestV1,
  encodeLaneHolderDeliveryReceiptV1,
  encodeLaneProtocolCommitReceiptV1,
  encodeLaneServerActivationReceiptV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import type {
  AggregateLaneActivationChildReceiptV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  RotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes/rotation';
import {
  buildR102HolderDeliveryReceipt,
  buildR102LaneEnrollmentFixture,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';
import {
  buildLinkedDeviceEnrollmentChildReceiptV1,
  buildLinkedDeviceEnrollmentReceiptV1,
  buildLinkedDeviceSessionClaimV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '../../packages/shared-ts/src/device-linking/digests';
import {
  buildR103DeviceLinkFixture,
  buildR103TargetReadySourceFixture,
} from './helpers/deviceLinkContracts.fixtures';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '../../packages/shared-ts/src/threshold/sessionPolicy';

const signerMigrations = listD1MigrationFiles('d1-signer');
const scope = {
  namespace: 'linked-auth-test',
  orgId: 'linked-auth-org',
  projectId: 'linked-auth-project',
  envId: 'linked-auth-env',
} as const;

test.describe('D1 linked-device authorization', () => {
  test('issues the active linked enrollment authorization once and replays its identity', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const linked = buildR103DeviceLinkFixture();
      const { targetReady } = buildR103TargetReadySourceFixture(linked);
      const lifecycle = new CloudflareD1LaneLifecycleStore({
        database: temporary.database,
        scope,
        now: () => linked.receipt.activatedAtMs,
      });
      const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore: lifecycle });
      await gateway.prepareLaneEnrollmentV1({
        manifest: targetReady.manifest,
        children: targetReady.children,
      });
      const child = await completeChild(gateway, targetReady.children[0]);
      const manifestDigestB64u = parseDigestB64u(
        await computeLaneEnrollmentManifestDigestV1(targetReady.manifest),
      );
      await gateway.commitLaneEnrollmentActivationV1({
        kind: 'commit_lane_enrollment_activation_v1',
        enrollmentId: targetReady.manifest.enrollmentId,
        walletId: targetReady.manifest.walletId,
        manifestDigestB64u,
        orderedChildReceipts: [child],
        orderedPredecessorRetirements: [],
        activatedAtMs: linked.receipt.activatedAtMs,
      });
      const product = (
        await lifecycle.listEnrollmentProductEpochs(targetReady.manifest.enrollmentId)
      )[0];
      if (!product || product.state !== 'active') {
        throw new Error('linked issuer fixture product is not active');
      }
      const receipt = buildLinkedDeviceEnrollmentReceiptV1({
        enrollmentId: linked.approval.enrollmentId,
        walletId: linked.approval.walletId,
        deviceId: linked.approval.deviceId,
        manifestDigestB64u,
        aggregateReceiptDigestB64u: product.aggregateActivationReceiptDigestB64u,
        orderedChildReceipts: [
          buildLinkedDeviceEnrollmentChildReceiptV1({
            enrollmentId: linked.approval.enrollmentId,
            walletId: linked.approval.walletId,
            walletKeyId: product.walletKeyId,
            keyFamily: product.keyFamily,
            targetLaneId: product.laneId,
            targetLaneShareEpoch: product.laneShareEpoch,
            materialActivation: product.materialActivation,
            receiptDigestB64u: child.serverActivationReceiptDigestB64u,
            transcriptHashB64u: manifestDigestB64u,
            deliveredAtMs: linked.receipt.activatedAtMs,
          }),
        ],
        activatedAtMs: linked.receipt.activatedAtMs,
      });
      const activeSession = await buildActiveLinkedDeviceSession(linked, receipt);
      const store = new CloudflareD1AuthorizationStore({
        database: temporary.database,
        namespace: scope.namespace,
        walletSignerScope: scope,
      });
      const authorization = new AuthorizationService({
        policy: capabilityPolicyPort,
        sessions: store,
        evidence: store,
        grants: store,
        authorizedOperations: store,
        audit: store,
      });
      const tenantId = required(parseTenantId, 'tenant-linked-issuer');
      const issuer = new D1LinkedDeviceWalletSessionIssuerV1({
        tenantId,
        authorizationService: authorization,
        laneLifecycle: lifecycle,
      });
      const expiredIssuer = new D1LinkedDeviceWalletSessionIssuerV1({
        tenantId: required(parseTenantId, 'tenant-linked-issuer-expired'),
        authorizationService: authorization,
        laneLifecycle: lifecycle,
      });
      await expect(
        expiredIssuer.issueForActiveSessionV1({
          session: activeSession,
          requestedAtMs: linked.receipt.activatedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
        }),
      ).rejects.toThrow('linked-device Wallet Session activation is too old to authorize');
      await issuer.issueForActiveSessionV1({
        session: activeSession,
        requestedAtMs: linked.receipt.activatedAtMs + 1,
      });
      const expectedIssuance = {
        tenantId,
        deviceId: linked.approval.deviceId,
        walletId: linked.approval.walletId,
        enrollmentId: linked.approval.enrollmentId,
        keyManifestDigestB64u: manifestDigestB64u,
        permission: linked.approval.permission,
        revocationEpoch: product.revocationEpoch,
        remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
        issuedAtMs: linked.receipt.activatedAtMs,
        expiresAtMs: linked.receipt.activatedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
      } as const;
      const identity = await deriveLinkedDeviceWalletSessionIdentityV1(expectedIssuance);
      await expect(
        authorization.getLinkedDeviceWalletSessionStatus({
          tenantId,
          deviceId: linked.approval.deviceId,
          ...identity,
          nowMs: linked.receipt.activatedAtMs + 1,
        }),
      ).resolves.toMatchObject({
        kind: 'active',
        walletId: linked.approval.walletId,
        enrollmentId: linked.approval.enrollmentId,
        deviceId: linked.approval.deviceId,
        keyManifestDigestB64u: manifestDigestB64u,
        revocationEpoch: product.revocationEpoch,
        remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
        expiresAtMs: expectedIssuance.expiresAtMs,
      });
      await authorization.revokeLinkedDeviceWalletSession({
        tenantId,
        deviceId: linked.approval.deviceId,
        ...identity,
        nowMs: linked.receipt.activatedAtMs + 2,
      });
      await expect(
        issuer.issueForActiveSessionV1({
          session: activeSession,
          requestedAtMs: linked.receipt.activatedAtMs + DEFAULT_WALLET_SESSION_TTL_MS + 1,
        }),
      ).resolves.toBeUndefined();
      await expect(
        authorization.getLinkedDeviceWalletSessionStatus({
          tenantId,
          deviceId: linked.approval.deviceId,
          ...identity,
          nowMs: linked.receipt.activatedAtMs + 3,
        }),
      ).resolves.toMatchObject({ kind: 'revoked' });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('issues an exact linked authorization, consumes its quota, and revokes atomically', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, signerMigrations);
      const fixture = buildR102LaneEnrollmentFixture();
      const lifecycle = new CloudflareD1LaneLifecycleStore({
        database: temporary.database,
        scope,
        now: () => 5_000,
      });
      const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore: lifecycle });
      await activateFixture(gateway, fixture);
      const store = new CloudflareD1AuthorizationStore({
        database: temporary.database,
        namespace: scope.namespace,
        walletSignerScope: scope,
      });
      const service = new AuthorizationService({
        policy: capabilityPolicyPort,
        sessions: store,
        evidence: store,
        grants: store,
        authorizedOperations: store,
        audit: store,
      });
      const tenantId = required(parseTenantId, 'tenant-linked-auth');
      const deviceId = required(parseLinkedDeviceId, 'device-linked-auth');
      const enrollmentId = required(
        parseLinkedDeviceEnrollmentId,
        String(fixture.manifest.enrollmentId),
      );
      const manifestDigest = parseDigestB64u(
        await computeLaneEnrollmentManifestDigestV1(fixture.manifest),
      );
      const issued = await service.issueLinkedDeviceWalletSession({
        tenantId,
        deviceId,
        walletId: fixture.manifest.walletId,
        enrollmentId,
        keyManifestDigestB64u: manifestDigest,
        permission: {
          kind: 'owner_equivalent_signing',
          administrationScope: 'signing_only',
          localUserPresence: 'required',
        },
        revocationEpoch: 0,
        remainingUses: 2,
        issuedAtMs: 5_001,
        expiresAtMs: 90_000,
      });
      const authorizationId = issued.authorization.authorizationGrantRef.authorizationId;
      const walletSessionId = issued.authorization.walletSessionId;
      const quotaId = issued.authorization.quotaId;
      await expect(
        service.issueLinkedDeviceWalletSession({
          tenantId,
          deviceId,
          walletId: fixture.manifest.walletId,
          enrollmentId,
          keyManifestDigestB64u: manifestDigest,
          permission: issued.authorization.permission,
          revocationEpoch: 0,
          remainingUses: 2,
          issuedAtMs: 5_001,
          expiresAtMs: 90_000,
        }),
      ).resolves.toEqual(issued);
      const product = (
        await lifecycle.listEnrollmentProductEpochs(fixture.manifest.enrollmentId)
      )[0];
      if (!product || product.state !== 'active')
        throw new Error('active fixture product is missing');
      const operation = buildCapabilityOperationEnvelope({
        tenantId,
        principalId: issued.authorization.principalId,
        capabilityId: required(parseCapabilityId, 'capability-linked-auth-test'),
        operationId: required(parseCapabilityOperationId, 'operation-linked-auth-test'),
        operation: buildNearEd25519MpcOperationRef('near.sign_transaction'),
        digests: {
          laneDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(1))),
          intentDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(2))),
          displayDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(3))),
        },
      });
      const material = {
        kind: 'linked_device_lane' as const,
        walletId: fixture.manifest.walletId,
        enrollmentId,
        deviceId,
        walletKeyId: product.walletKeyId,
        laneId: product.laneId,
        laneShareEpoch: product.laneShareEpoch,
        revocationEpoch: product.revocationEpoch,
        materialActivation: routerAbMpcMaterialActivationRefToWire({
          kind: 'mpc_material_activation_ref',
          activationId: String(product.materialActivation.activationId),
          capability: String(product.materialActivation.capability),
          materialOwner: String(product.materialActivation.materialOwner),
          keyBinding: String(product.materialActivation.keyBinding),
          lifecycleBinding: String(product.materialActivation.lifecycleBinding),
          signingWorker: String(product.materialActivation.signingWorker),
        }),
      };
      const claimInput = {
        tenantId,
        authorizedOperationId: required(parseAuthorizedOperationId, 'authorized-linked-auth-test'),
        auditEventId: required(parseAuthorizationAuditEventId, 'audit-linked-auth-test'),
        operation,
        authorization: {
          kind: 'authorization_grant' as const,
          authorizationGrantRef: issued.authorization.authorizationGrantRef,
        },
        quota: { kind: 'consume_reusable_wallet_session' as const, quotaId },
        claimedAtMs: 5_002,
      };
      await expect(
        service.admitAuthorizedOperation({ operation: claimInput, material }),
      ).resolves.toMatchObject({
        kind: 'claimed',
      });
      await expect(
        temporary.database
          .prepare(
            `SELECT remaining_uses FROM linked_device_wallet_session_quotas WHERE tenant_id = ? AND quota_id = ?`,
          )
          .bind(tenantId, quotaId)
          .first<{ readonly remaining_uses?: unknown }>(),
      ).resolves.toMatchObject({ remaining_uses: 1 });
      await expect(
        temporary.database
          .prepare(
            `SELECT authorization_grant_kind, material_activation_id,
                    material_activation_capability, material_activation_owner,
                    material_activation_key_binding, material_activation_lifecycle_binding,
                    material_activation_signing_worker, linked_wallet_id,
                    linked_enrollment_id, linked_device_id, linked_wallet_key_id,
                    linked_lane_id, linked_lane_share_epoch, linked_revocation_epoch,
                    linked_scope_org_id, linked_scope_project_id, linked_scope_env_id
               FROM authorized_operation_audit_events
              WHERE namespace = ? AND tenant_id = ? AND audit_event_id = ?`,
          )
          .bind(scope.namespace, tenantId, claimInput.auditEventId)
          .first<Record<string, unknown>>(),
      ).resolves.toMatchObject({
        authorization_grant_kind: 'linked_device_wallet_session_authorization_v1',
        material_activation_id: material.materialActivation.activation_id,
        material_activation_capability: material.materialActivation.capability,
        material_activation_owner: material.materialActivation.material_owner,
        material_activation_key_binding: material.materialActivation.key_binding,
        material_activation_lifecycle_binding: material.materialActivation.lifecycle_binding,
        material_activation_signing_worker: material.materialActivation.signing_worker,
        linked_wallet_id: material.walletId,
        linked_enrollment_id: material.enrollmentId,
        linked_device_id: material.deviceId,
        linked_wallet_key_id: material.walletKeyId,
        linked_lane_id: material.laneId,
        linked_lane_share_epoch: material.laneShareEpoch,
        linked_revocation_epoch: material.revocationEpoch,
        linked_scope_org_id: scope.orgId,
        linked_scope_project_id: scope.projectId,
        linked_scope_env_id: scope.envId,
      });
      const collisionValues = [
        scope.namespace,
        tenantId,
        'authorized-linked-scope-collision',
        'audit-linked-scope-collision',
        issued.authorization.principalId,
        operation.capabilityId,
        operation.operation.capabilityKind,
        operation.operation.operationKind,
        operation.operationId,
        'fingerprint-linked-scope-collision',
        operation.digests.laneDigest,
        operation.digests.intentDigest,
        operation.digests.displayDigest,
        'authorization_grant',
        issued.authorization.authorizationGrantRef.authorizationId,
        null,
        quotaId,
        'consume_reusable_wallet_session',
        'linked_device_wallet_session_authorization_v1',
        'claimed',
        'pending',
        null,
        null,
        null,
        null,
        5_005,
        null,
        material.materialActivation.activation_id,
        material.materialActivation.capability,
        material.materialActivation.material_owner,
        material.materialActivation.key_binding,
        material.materialActivation.lifecycle_binding,
        material.materialActivation.signing_worker,
        material.walletId,
        material.enrollmentId,
        material.deviceId,
        material.walletKeyId,
        material.laneId,
        material.laneShareEpoch,
        material.revocationEpoch,
        'collision-org',
        'collision-project',
        'collision-env',
      ];
      await expectLinkedOperationRejected(temporary.database, collisionValues);
      const wrongWallet = [...collisionValues];
      wrongWallet[2] = 'authorized-linked-wallet-mismatch';
      wrongWallet[3] = 'audit-linked-wallet-mismatch';
      wrongWallet[9] = 'fingerprint-linked-wallet-mismatch';
      wrongWallet[40] = scope.orgId;
      wrongWallet[41] = scope.projectId;
      wrongWallet[42] = scope.envId;
      wrongWallet[33] = 'wallet-linked-mismatch';
      await expectLinkedOperationRejected(temporary.database, wrongWallet);
      const wrongEnrollment = [...collisionValues];
      wrongEnrollment[2] = 'authorized-linked-enrollment-mismatch';
      wrongEnrollment[3] = 'audit-linked-enrollment-mismatch';
      wrongEnrollment[9] = 'fingerprint-linked-enrollment-mismatch';
      wrongEnrollment[40] = scope.orgId;
      wrongEnrollment[41] = scope.projectId;
      wrongEnrollment[42] = scope.envId;
      wrongEnrollment[34] = 'enrollment-linked-mismatch';
      await expectLinkedOperationRejected(temporary.database, wrongEnrollment);
      const wrongRevocation = [...collisionValues];
      wrongRevocation[2] = 'authorized-linked-revocation-mismatch';
      wrongRevocation[3] = 'audit-linked-revocation-mismatch';
      wrongRevocation[9] = 'fingerprint-linked-revocation-mismatch';
      wrongRevocation[40] = scope.orgId;
      wrongRevocation[41] = scope.projectId;
      wrongRevocation[42] = scope.envId;
      wrongRevocation[39] = 1;
      await expectLinkedOperationRejected(temporary.database, wrongRevocation);
      const wrongWalletKey = [...collisionValues];
      wrongWalletKey[2] = 'authorized-linked-wallet-key-mismatch';
      wrongWalletKey[3] = 'audit-linked-wallet-key-mismatch';
      wrongWalletKey[9] = 'fingerprint-linked-wallet-key-mismatch';
      wrongWalletKey[40] = scope.orgId;
      wrongWalletKey[41] = scope.projectId;
      wrongWalletKey[42] = scope.envId;
      wrongWalletKey[36] = 'wallet-key-linked-mismatch';
      await expectLinkedOperationRejected(temporary.database, wrongWalletKey);
      const wrongLaneEpoch = [...collisionValues];
      wrongLaneEpoch[2] = 'authorized-linked-lane-epoch-mismatch';
      wrongLaneEpoch[3] = 'audit-linked-lane-epoch-mismatch';
      wrongLaneEpoch[9] = 'fingerprint-linked-lane-epoch-mismatch';
      wrongLaneEpoch[40] = scope.orgId;
      wrongLaneEpoch[41] = scope.projectId;
      wrongLaneEpoch[42] = scope.envId;
      wrongLaneEpoch[38] = 'lane-share-epoch-linked-mismatch';
      await expectLinkedOperationRejected(temporary.database, wrongLaneEpoch);
      await expect(
        service.admitAuthorizedOperation({ operation: claimInput, material }),
      ).resolves.toMatchObject({
        kind: 'operation_in_progress',
      });
      await service.revokeLinkedDeviceWalletSession({
        tenantId,
        deviceId,
        authorizationId,
        walletSessionId,
        quotaId,
        nowMs: 5_003,
      });
      await expect(
        service.getLinkedDeviceWalletSessionStatus({
          tenantId,
          deviceId,
          authorizationId,
          walletSessionId,
          quotaId,
          nowMs: 5_004,
        }),
      ).resolves.toMatchObject({ kind: 'revoked', revokedAtMs: 5_003 });
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });
});

async function buildActiveLinkedDeviceSession(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
  receipt: ReturnType<typeof buildLinkedDeviceEnrollmentReceiptV1>,
) {
  const claim = buildLinkedDeviceSessionClaimV1({
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
    claimedAtMs: 1_500,
    claimExpiresAtMs: fixture.payload.expiresAtMs,
  });
  return parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: {
      state: 'active',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      activatedAtMs: receipt.activatedAtMs,
    },
    revision: 4,
    claimTranscript: {
      digestB64u: await computeLinkedDeviceSessionClaimDigestV1(claim),
      value: claim,
    },
    approvalTranscript: {
      digestB64u: await computeLinkedDeviceApprovalDigestV1(fixture.approval),
      value: fixture.approval,
    },
    aggregateReceipt: receipt,
    createdAtMs: fixture.payload.issuedAtMs,
    updatedAtMs: receipt.activatedAtMs,
  });
}

async function activateFixture(
  gateway: CloudflareD1LaneEnrollmentGateway,
  fixture: ReturnType<typeof buildR102LaneEnrollmentFixture>,
): Promise<void> {
  await gateway.prepareLaneEnrollmentV1(fixture);
  const children: AggregateLaneActivationChildReceiptV1[] = [];
  for (const job of fixture.children) children.push(await completeChild(gateway, job));
  await gateway.commitLaneEnrollmentActivationV1({
    kind: 'commit_lane_enrollment_activation_v1',
    enrollmentId: fixture.manifest.enrollmentId,
    walletId: fixture.manifest.walletId,
    manifestDigestB64u: await computeLaneEnrollmentManifestDigestV1(fixture.manifest),
    orderedChildReceipts: [children[0]!, children[1]!],
    orderedPredecessorRetirements: [],
    activatedAtMs: 5_000,
  });
}

async function completeChild(
  gateway: CloudflareD1LaneEnrollmentGateway,
  job: RotatableSigningLaneJobV1,
): Promise<AggregateLaneActivationChildReceiptV1> {
  const protocolReceipt = buildR102ProtocolCommitReceipt(job);
  const protocol = await gateway.recordLaneProtocolCommitV1({
    receipt: protocolReceipt,
    expectedVersion: 1,
  });
  if (protocol.outcome === 'conflict') throw new Error('protocol fixture conflicted');
  const holderReceipt = buildR102HolderDeliveryReceipt(job);
  const holder = await gateway.recordLaneHolderDeliveryV1({
    receipt: holderReceipt,
    expectedVersion: protocol.version,
  });
  if (holder.outcome === 'conflict') throw new Error('holder fixture conflicted');
  const serverReceipt = buildR102ServerActivationReceipt(job);
  const server = await gateway.activateLaneServerMaterialV1({
    receipt: serverReceipt,
    expectedVersion: holder.version,
  });
  if (server.outcome === 'conflict') throw new Error('server fixture conflicted');
  return {
    operationId: job.operationId,
    walletKeyId: job.walletKeyId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivation: serverReceipt.targetMaterialActivation,
    protocolCommitReceiptDigestB64u: await digestReceipt(protocolReceipt),
    holderDeliveryReceiptDigestB64u: await digestReceipt(holderReceipt),
    serverActivationReceiptDigestB64u: await digestReceipt(serverReceipt),
  };
}

async function digestReceipt(
  receipt:
    | LaneProtocolCommitReceiptV1
    | LaneHolderDeliveryReceiptV1
    | LaneServerActivationReceiptV1,
): Promise<string> {
  const encoded =
    receipt.kind === 'lane_protocol_commit_receipt_v1'
      ? encodeLaneProtocolCommitReceiptV1(receipt)
      : receipt.kind === 'lane_holder_delivery_receipt_v1'
        ? encodeLaneHolderDeliveryReceiptV1(receipt)
        : encodeLaneServerActivationReceiptV1(receipt);
  return base64UrlEncode(await sha256Bytes(encoded));
}

async function expectLinkedOperationRejected(
  database: D1DatabaseLike,
  values: readonly unknown[],
): Promise<void> {
  const placeholders = values.map(sqlPlaceholder).join(', ');
  await expect(
    database
      .prepare(
        `INSERT INTO authorized_operations (
           namespace, tenant_id, authorized_operation_id, audit_event_id,
           principal_id, capability_id, capability_kind, operation_kind, operation_id,
           operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
           authorization_source_kind, authorization_id, evidence_set_digest,
           quota_id, quota_kind, authorization_grant_kind, lifecycle_kind, result_kind,
           result_digest, result_status, result_content_type, result_body_text,
           claimed_at_ms, completed_at_ms, material_activation_id,
           material_activation_capability, material_activation_owner,
           material_activation_key_binding, material_activation_lifecycle_binding,
           material_activation_signing_worker, linked_wallet_id, linked_enrollment_id,
           linked_device_id, linked_wallet_key_id, linked_lane_id, linked_lane_share_epoch,
           linked_revocation_epoch, linked_scope_org_id, linked_scope_project_id,
           linked_scope_env_id
         ) VALUES (${placeholders})`,
      )
      .bind(...values)
      .run(),
  ).rejects.toThrow('authorization_linked_device_rejected');
}

function sqlPlaceholder(): string {
  return '?';
}

function required<T>(
  parser: (
    value: unknown,
  ) => { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: Error },
  value: unknown,
): T {
  const parsed = parser(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

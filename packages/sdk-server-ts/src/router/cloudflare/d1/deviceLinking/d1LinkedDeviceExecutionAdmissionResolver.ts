import type {
  AuthorizationGrantPort,
  IssuedLinkedDeviceWalletSession,
} from '../../../../authorization/service';
import type {
  ActiveLinkedDeviceEnrollmentExecutionRecordV1,
  ActiveLinkedDeviceExecutionProjectionV1,
  LinkedDeviceExecutionAdmissionResolverV1,
  LinkedDeviceExecutionProjectionResult,
} from '../../../domains/signingOperations/walletExecutionAdmission';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import {
  buildActiveSigningLaneLifecycle,
  buildActiveWalletKeyLifecycle,
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildLinkedDeviceSigningLaneRecord,
  parseWalletKeyVersion,
} from '@shared/signing-lanes/recordParsers';
import type {
  EcdsaAdditiveLaneJobV1,
  LaneProtocolCommitReceiptV1,
  LaneProductEpochRecordV1,
  LaneProtocolRecordV1,
} from '@shared/signing-lanes';
import { buildLinkedDeviceEcdsaNormalSigningScopeV1 } from '@shared/signing-lanes';
import { computeLaneParticipantSetBindingDigestV1 } from '@shared/signing-lanes/participantDigest';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseLaneEnrollmentId, type LaneEnrollmentId } from '@shared/signing-lanes/ids';
import {
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import {
  parseWebAuthnCredentialIdB64u,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';
import { LaneLifecycleStoreNormalSigningLaneMaterialResolverV1 } from '../../signingLanes/cloudflareLaneCurveExecution';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId, MpcMaterialActivationRef } from '@shared/utils/domainIds';

export type D1LinkedDeviceCredentialResolverV1 = {
  readLinkedDeviceCredentialIdV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<WebAuthnCredentialIdB64u | string | null>;
};

export type D1LinkedDeviceExecutionAdmissionResolverOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly authorization: Pick<
    AuthorizationGrantPort,
    'readLinkedDeviceWalletSessionAuthorization'
  >;
  readonly credentials: D1LinkedDeviceCredentialResolverV1;
  readonly nowV1: () => number;
};

/**
 * Projects one active linked lane from the scoped D1 lane records and grant
 * record. Every identity used by SigningWorker is selected by the complete
 * wallet/enrollment/lane/material tuple supplied by the claimed operation.
 */
export class D1LinkedDeviceExecutionAdmissionResolverV1 implements LinkedDeviceExecutionAdmissionResolverV1 {
  private readonly authorization: D1LinkedDeviceExecutionAdmissionResolverOptionsV1['authorization'];
  private readonly credentials: D1LinkedDeviceCredentialResolverV1;
  private readonly nowV1: () => number;
  private readonly lanes: CloudflareD1LaneLifecycleStore;
  private readonly materialResolver: LaneLifecycleStoreNormalSigningLaneMaterialResolverV1;

  constructor(options: D1LinkedDeviceExecutionAdmissionResolverOptionsV1) {
    this.authorization = options.authorization;
    this.credentials = options.credentials;
    this.nowV1 = options.nowV1;
    this.lanes = new CloudflareD1LaneLifecycleStore({
      database: options.database,
      scope: options.scope,
      now: options.nowV1,
    });
    this.materialResolver = new LaneLifecycleStoreNormalSigningLaneMaterialResolverV1(this.lanes);
  }

  async resolveActiveLinkedDeviceExecutionV1(
    input: Parameters<
      LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
    >[0],
  ): Promise<LinkedDeviceExecutionProjectionResult> {
    try {
      const nowMs = this.nowV1();
      const laneEnrollmentId = parseLaneEnrollmentId(String(input.enrollmentId));
      if (!laneEnrollmentId.ok) return refused('linked_enrollment_mismatch');
      const product = await this.lanes.getProductEpoch({
        walletId: input.walletId,
        walletKeyId: input.walletKeyId,
        laneId: input.laneId,
        laneShareEpoch: input.laneShareEpoch,
      });
      if (!product || product.state !== 'active') return refused('lane_inactive');
      if (
        product.walletId !== input.walletId ||
        product.walletKeyId !== input.walletKeyId ||
        product.laneId !== input.laneId ||
        product.laneShareEpoch !== input.laneShareEpoch ||
        String(product.enrollmentId) !== String(laneEnrollmentId.value) ||
        !sameMaterialActivation(product.materialActivation, input.materialActivation)
      ) {
        return refused('linked_product_mismatch');
      }

      const material = await this.materialResolver.resolveV1({
        lookup: {
          walletId: input.walletId,
          walletKeyId: input.walletKeyId,
          laneId: input.laneId,
          laneShareEpoch: input.laneShareEpoch,
        },
        materialActivation: input.materialActivation,
        keyFamily: product.keyFamily,
      });
      const protocol = await this.lanes.getProtocol(product.operationId);
      if (!protocol || protocol.value.lifecycle.state !== 'active') {
        return refused('lane_inactive');
      }
      const protocolCommitReceipt =
        product.keyFamily === 'ecdsa_secp256k1'
          ? await this.lanes.getProtocolCommitReceipt(product.operationId)
          : null;
      if (product.keyFamily === 'ecdsa_secp256k1' && protocolCommitReceipt === null) {
        return refused('linked_execution_unavailable');
      }
      const issued = await this.authorization.readLinkedDeviceWalletSessionAuthorization({
        tenantId: input.tenantId,
        deviceId: input.deviceId,
        authorizationId: input.authorizationId,
        walletSessionId: input.walletSessionId,
        quotaId: input.quotaId,
        nowMs,
      });
      if (!issued) return refused('authorization_grant_mismatch');
      return await this.projectActiveExecution({
        input,
        issued,
        product,
        protocol: protocol.value,
        protocolCommitReceipt,
        material,
        laneEnrollmentId: laneEnrollmentId.value,
      });
    } catch {
      return refused('linked_execution_unavailable');
    }
  }

  private async projectActiveExecution(projectionInput: {
    readonly input: Parameters<
      LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
    >[0];
    readonly issued: IssuedLinkedDeviceWalletSession;
    readonly product: Extract<LaneProductEpochRecordV1, { readonly state: 'active' }>;
    readonly protocol: LaneProtocolRecordV1;
    readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1 | null;
    readonly material: Awaited<
      ReturnType<LaneLifecycleStoreNormalSigningLaneMaterialResolverV1['resolveV1']>
    >;
    readonly laneEnrollmentId: LaneEnrollmentId;
  }): Promise<LinkedDeviceExecutionProjectionResult> {
    const { input, issued, product, protocol, protocolCommitReceipt, material, laneEnrollmentId } =
      projectionInput;
    const authorization = issued.authorization;
    const quota = issued.quota;
    if (
      authorization.tenantId !== input.tenantId ||
      authorization.walletId !== input.walletId ||
      authorization.enrollmentId !== input.enrollmentId ||
      authorization.deviceId !== input.deviceId ||
      authorization.authorizationGrantRef.authorizationId !== input.authorizationId ||
      authorization.walletSessionId !== input.walletSessionId ||
      authorization.quotaId !== input.quotaId ||
      quota.tenantId !== input.tenantId ||
      quota.walletSessionId !== authorization.walletSessionId ||
      quota.quotaId !== authorization.quotaId ||
      quota.remainingUses <= 0
    ) {
      return refused('authorization_grant_mismatch');
    }
    if (authorization.expiresAtMs <= this.nowV1() || quota.expiresAtMs <= this.nowV1()) {
      return refused('authorization_expired');
    }
    if (authorization.revocationEpoch !== product.revocationEpoch) {
      return refused('revocation_epoch_mismatch');
    }
    if (
      product.walletId !== authorization.walletId ||
      String(product.enrollmentId) !== String(laneEnrollmentId) ||
      product.laneKind !== 'linked_device'
    ) {
      return refused('linked_product_mismatch');
    }
    const manifestDigest = parseDigestB64u(product.aggregateManifestDigestB64u);
    if (String(manifestDigest) !== String(authorization.keyManifestDigestB64u)) {
      return refused('linked_product_mismatch');
    }
    const credentialRaw = await this.credentials.readLinkedDeviceCredentialIdV1({
      walletId: input.walletId,
      enrollmentId: input.enrollmentId,
      deviceId: input.deviceId,
    });
    if (!credentialRaw) return refused('linked_execution_unavailable');
    const credentialId = parseCredentialId(credentialRaw);
    const participantBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
      holderParticipant: product.holderParticipant,
      signingWorkerParticipant: product.signingWorkerParticipant,
    });
    if (participantBindingDigestB64u !== product.participantSetBindingDigestB64u) {
      return refused('linked_participant_mismatch');
    }
    const activationReceiptDigestB64u = parseDigestB64u(
      product.aggregateActivationReceiptDigestB64u,
    );
    const lane = buildLinkedDeviceSigningLaneRecord({
      walletId: product.walletId,
      walletKeyId: product.walletKeyId,
      laneId: product.laneId,
      laneShareEpoch: product.laneShareEpoch,
      participantBindingDigestB64u,
      holderParticipant: product.holderParticipant,
      serverParticipant: product.signingWorkerParticipant,
      lifecycle: buildActiveSigningLaneLifecycle({
        revocationEpoch: product.revocationEpoch,
        activatedAtMs: product.activatedAtMs,
        activationReceiptDigestB64u,
      }),
      linkedDeviceId: input.deviceId,
    });
    const walletKey = buildWalletKey(protocol, product);
    const enrollment: ActiveLinkedDeviceEnrollmentExecutionRecordV1 = {
      kind: 'active_linked_device_enrollment_v1',
      walletId: product.walletId,
      enrollmentId: input.enrollmentId,
      deviceId: input.deviceId,
      keyManifestDigestB64u: manifestDigest,
      credentialIdB64u: credentialId,
      revocationEpoch: product.revocationEpoch,
      lifecycle: { state: 'active', activatedAtMs: product.activatedAtMs },
    };
    const commonProjection = {
      kind: 'active_linked_device_execution_projection_v1' as const,
      authorization,
      enrollment,
      lane,
      product,
      materialActivation: product.materialActivation,
      verifiedLaneParticipantBindingDigestB64u: participantBindingDigestB64u,
      verifiedActivationReceiptDigestB64u: activationReceiptDigestB64u,
      materialSource: material.source,
    };
    let projection: ActiveLinkedDeviceExecutionProjectionV1;
    if (product.keyFamily === 'ecdsa_secp256k1') {
      if (
        protocol.job.keyFamily !== 'ecdsa_secp256k1' ||
        walletKey.keyFamily !== 'ecdsa_secp256k1' ||
        protocolCommitReceipt === null
      ) {
        return refused('linked_product_mismatch');
      }
      projection = {
        ...commonProjection,
        walletKey,
        ecdsaNormalSigningScope: buildLinkedDeviceEcdsaScope({
          product,
          job: protocol.job,
          lifecycle: protocol.lifecycle,
          protocolCommitReceipt,
          materialActivation: product.materialActivation,
        }),
      };
    } else {
      if (protocol.job.keyFamily !== 'ed25519' || walletKey.keyFamily !== 'ed25519') {
        return refused('linked_product_mismatch');
      }
      projection = { ...commonProjection, walletKey };
    }
    return { kind: 'projected', projection };
  }
}

function buildLinkedDeviceEcdsaScope(input: {
  readonly product: Extract<LaneProductEpochRecordV1, { readonly state: 'active' }>;
  readonly job: EcdsaAdditiveLaneJobV1;
  readonly lifecycle: LaneProtocolRecordV1['lifecycle'];
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly materialActivation: MpcMaterialActivationRef;
}) {
  const { product, job, lifecycle, protocolCommitReceipt, materialActivation } = input;
  if (lifecycle.state !== 'active') {
    throw new Error('linked ECDSA protocol lifecycle is not active');
  }
  if (
    product.keyFamily !== 'ecdsa_secp256k1' ||
    product.laneKind !== 'linked_device' ||
    job.operationId !== product.operationId ||
    job.enrollmentId !== product.enrollmentId ||
    job.walletId !== product.walletId ||
    job.walletKeyId !== product.walletKeyId ||
    job.target.laneId !== product.laneId ||
    job.target.laneShareEpoch !== product.laneShareEpoch ||
    job.target.laneKind !== product.laneKind ||
    job.targetMaterialActivationId !== product.targetMaterialActivationId ||
    job.targetHolder.participantId !== product.holderParticipant.participantId ||
    job.targetHolder.participantBindingDigestB64u !==
      product.holderParticipant.participantBindingDigestB64u ||
    job.targetHolder.custodyBindingId !== product.holderParticipant.custodyBindingId ||
    job.targetHolder.custodyBindingDigestB64u !==
      product.holderParticipant.custodyBindingDigestB64u ||
    job.targetHolder.hpkePublicKeyB64u !== product.holderParticipant.hpkePublicKeyB64u ||
    job.targetHolder.hpkePublicKeyDigestB64u !==
      product.holderParticipant.hpkePublicKeyDigestB64u ||
    job.targetSigningWorker.participantId !== product.signingWorkerParticipant.participantId ||
    job.targetSigningWorker.participantBindingDigestB64u !==
      product.signingWorkerParticipant.participantBindingDigestB64u ||
    job.targetSigningWorker.recipientKeyId !== product.signingWorkerParticipant.recipientKeyId ||
    job.targetSigningWorker.hpkePublicKeyB64u !==
      product.signingWorkerParticipant.hpkePublicKeyB64u ||
    job.targetSigningWorker.hpkePublicKeyDigestB64u !==
      product.signingWorkerParticipant.hpkePublicKeyDigestB64u ||
    !sameMaterialActivation(product.materialActivation, materialActivation) ||
    materialActivation.activationId !== job.targetMaterialActivationId ||
    String(materialActivation.signingWorker) !==
      String(product.signingWorkerParticipant.participantId)
  ) {
    throw new Error('linked ECDSA active product does not match its admitted lane job');
  }
  if (
    protocolCommitReceipt.keyFamily !== 'ecdsa_secp256k1' ||
    protocolCommitReceipt.operationId !== product.operationId ||
    protocolCommitReceipt.enrollmentId !== product.enrollmentId ||
    protocolCommitReceipt.walletId !== product.walletId ||
    protocolCommitReceipt.walletKeyId !== product.walletKeyId ||
    protocolCommitReceipt.targetLaneId !== product.laneId ||
    protocolCommitReceipt.targetLaneShareEpoch !== product.laneShareEpoch ||
    protocolCommitReceipt.targetMaterialActivationId !== product.targetMaterialActivationId ||
    protocolCommitReceipt.publicIdentityDigestB64u !== product.publicIdentityDigestB64u ||
    protocolCommitReceipt.holderRecipientKeyDigestB64u !==
      product.holderParticipant.hpkePublicKeyDigestB64u ||
    protocolCommitReceipt.serverRecipientKeyDigestB64u !==
      product.signingWorkerParticipant.hpkePublicKeyDigestB64u ||
    protocolCommitReceipt.transcriptHashB64u !== lifecycle.transcriptHashB64u
  ) {
    throw new Error('linked ECDSA protocol receipt does not match its active product');
  }
  return buildLinkedDeviceEcdsaNormalSigningScopeV1({
    walletId: product.walletId,
    walletKeyId: product.walletKeyId,
    enrollmentId: product.enrollmentId,
    operationId: product.operationId,
    laneId: product.laneId,
    laneShareEpoch: product.laneShareEpoch,
    revocationEpoch: product.revocationEpoch,
    targetMaterialActivationId: product.targetMaterialActivationId,
    materialActivation,
    targetCapability: job.targetCapability,
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(job.thresholdPublicKey33B64u),
    evmAddress: job.evmAddress,
    publicIdentityDigestB64u: parseDigestB64u(protocolCommitReceipt.publicIdentityDigestB64u),
    targetHolderPublicCommitmentB64u: parseSecp256k1CompressedPublicKeyB64u(
      protocolCommitReceipt.targetHolderPublicCommitmentB64u,
    ),
    targetServerPublicCommitmentB64u: parseSecp256k1CompressedPublicKeyB64u(
      protocolCommitReceipt.targetServerPublicCommitmentB64u,
    ),
    holderParticipantId: product.holderParticipant.participantId,
    signingWorkerParticipantId: product.signingWorkerParticipant.participantId,
    holderParticipantBindingDigestB64u: product.holderParticipant.participantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u:
      product.signingWorkerParticipant.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: product.holderParticipant.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: product.signingWorkerParticipant.hpkePublicKeyDigestB64u,
    signingWorkerRecipientKeyId: product.signingWorkerParticipant.recipientKeyId,
    signingWorkerHpkePublicKeyB64u: product.signingWorkerParticipant.hpkePublicKeyB64u,
    transcriptHashB64u: parseDigestB64u(protocolCommitReceipt.transcriptHashB64u),
    protocolCommitReceiptDigestB64u: parseDigestB64u(lifecycle.protocolCommitReceiptDigestB64u),
  });
}

function buildWalletKey(
  protocol: LaneProtocolRecordV1,
  product: Extract<LaneProductEpochRecordV1, { readonly state: 'active' }>,
) {
  const version = parseWalletKeyVersion(
    `wallet-key-version:linked-device:${String(product.laneShareEpoch)}`,
  );
  if (protocol.job.keyFamily === 'ed25519') {
    return buildEd25519WalletKeyRecord({
      walletId: product.walletId,
      walletKeyId: product.walletKeyId,
      walletKeyVersion: version,
      nearEd25519SigningKeyId: protocol.job.nearEd25519SigningKeyId,
      keyCreationSignerSlot: protocol.job.keyCreationSignerSlot,
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(protocol.job.registeredPublicKeyB64u),
      lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: product.activatedAtMs }),
    });
  }
  return buildEvmFamilyWalletKeyRecord({
    walletId: product.walletId,
    walletKeyId: product.walletKeyId,
    walletKeyVersion: version,
    evmFamilySigningKeySlotId: protocol.job.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      protocol.job.thresholdPublicKey33B64u,
    ),
    evmAddress: protocol.job.evmAddress,
    lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: product.activatedAtMs }),
  });
}

function parseCredentialId(raw: WebAuthnCredentialIdB64u | string): WebAuthnCredentialIdB64u {
  const parsed = parseWebAuthnCredentialIdB64u(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function sameMaterialActivation(
  left: MpcMaterialActivationRef,
  right: MpcMaterialActivationRef,
): boolean {
  return (
    left.activationId === right.activationId &&
    left.capability === right.capability &&
    left.materialOwner === right.materialOwner &&
    left.keyBinding === right.keyBinding &&
    left.lifecycleBinding === right.lifecycleBinding &&
    left.signingWorker === right.signingWorker
  );
}

function refused(
  reason: Extract<LinkedDeviceExecutionProjectionResult, { readonly kind: 'refused' }>['reason'],
): LinkedDeviceExecutionProjectionResult {
  return { kind: 'refused', reason };
}
